use std::{
    collections::HashMap,
    io::{self, Read, SeekFrom},
};

use futures::TryStreamExt;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use reqwest::{
    header::{CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, RANGE},
    multipart::Part,
    Method, StatusCode,
};
use serde::Deserialize;
use tracing::{debug, trace};
use url::Url;

// Mirrors JavaScript's encodeURIComponent: encode everything except
// A-Za-z0-9 and the unreserved characters - _ . ! ~ * ' ( )
const ENCODE_URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

use crate::{
    configuration::Endpoint, prelude::AttachmentIdentifier,
    proto::AttachmentPointer, push_service::HttpAuthOverride,
};

use super::{response::ReqwestExt, PushService, ServiceError};

#[derive(Debug, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentV2UploadAttributes {
    key: String,
    credential: String,
    acl: String,
    algorithm: String,
    date: String,
    policy: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentUploadForm {
    pub cdn: u32,
    pub key: String,
    pub headers: HashMap<String, String>,
    pub signed_upload_location: Url,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentDigest {
    pub digest: Vec<u8>,
    pub incremental_digest: Option<Vec<u8>>,
    pub incremental_mac_chunk_size: u64,
}

#[derive(Debug)]
pub struct ResumeInfo {
    pub content_range: Option<String>,
    pub content_start: u64,
}

impl PushService {
    pub async fn get_attachment(
        &mut self,
        ptr: &AttachmentPointer,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        let path = match ptr.attachment_identifier.as_ref() {
            Some(AttachmentIdentifier::CdnId(id)) => {
                format!("attachments/{}", id)
            },
            Some(AttachmentIdentifier::CdnKey(key)) => {
                format!(
                    "attachments/{}",
                    utf8_percent_encode(key, ENCODE_URI_COMPONENT)
                )
            },
            None => {
                return Err(ServiceError::InvalidFrame {
                    reason: "no attachment identifier in pointer",
                });
            },
        };
        self.get_from_cdn(ptr.cdn_number(), &path).await
    }

    #[tracing::instrument(skip(self))]
    pub(crate) async fn get_from_cdn(
        &mut self,
        cdn_id: u32,
        path: &str,
    ) -> Result<impl futures::io::AsyncRead + Send + Unpin, ServiceError> {
        let response_stream = self
            .request(
                Method::GET,
                Endpoint::cdn(cdn_id, path),
                HttpAuthOverride::Unidentified, // CDN requests are always without authentication
            )?
            .send()
            .await?
            .error_for_status()?
            .bytes_stream()
            .map_err(io::Error::other)
            .into_async_read();

        Ok(response_stream)
    }

    pub async fn download_transfer_archive(
        &mut self,
        cdn_id: u32,
        key: &str,
        range_start: u64,
    ) -> Result<(impl futures::io::AsyncRead + Send + Unpin, u64), ServiceError>
    {
        let builder = self.request(
            Method::GET,
            Endpoint::cdn(
                cdn_id,
                format!(
                    "attachments/{}",
                    utf8_percent_encode(key, ENCODE_URI_COMPONENT)
                ),
            ),
            HttpAuthOverride::Unidentified,
        )?;
        let builder = if range_start > 0 {
            builder.header(RANGE, format!("bytes={range_start}-"))
        } else {
            builder
        };

        let response = builder.send().await?.error_for_status()?;

        let total_bytes: u64 = if range_start == 0 {
            // Fresh start: total size comes from Content-Length.
            response
                .headers()
                .get(CONTENT_LENGTH)
                .ok_or(ServiceError::InvalidFrame {
                    reason: "Content-Length header absent",
                })?
                .to_str()
                .map_err(|_| ServiceError::InvalidFrame {
                    reason: "Content-Length is not valid UTF-8",
                })?
                .parse()
                .map_err(|_| ServiceError::InvalidFrame {
                    reason: "Content-Length is not a number",
                })?
        } else {
            // Resume: server must return 206 Partial Content, no multipart body,
            // and a Content-Range: bytes <start>-<end>/<total> from which we read
            // the total size.
            if response.status() != StatusCode::PARTIAL_CONTENT {
                return Err(ServiceError::UnhandledResponseCode {
                    http_code: response.status().as_u16(),
                });
            }

            if response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|ct| ct.contains("multipart"))
            {
                return Err(ServiceError::InvalidFrame {
                    reason:
                        "multipart response not supported for range requests",
                });
            }

            response
                .headers()
                .get(CONTENT_RANGE)
                .ok_or(ServiceError::InvalidFrame {
                    reason: "Content-Range header absent",
                })?
                .to_str()
                .map_err(|_| ServiceError::InvalidFrame {
                    reason: "Content-Range is not valid UTF-8",
                })?
                .rsplit('/')
                .next()
                .ok_or(ServiceError::InvalidFrame {
                    reason: "Content-Range header invalid",
                })?
                .parse()
                .map_err(|_| ServiceError::InvalidFrame {
                    reason: "Content-Range total is not a number",
                })?
        };

        let stream = response
            .bytes_stream()
            .map_err(io::Error::other)
            .into_async_read();

        Ok((stream, total_bytes))
    }

    pub(crate) async fn get_attachment_v4_upload_attributes(
        &mut self,
    ) -> Result<AttachmentUploadForm, ServiceError> {
        self.request(
            Method::GET,
            Endpoint::service("/v4/attachments/form/upload"),
            HttpAuthOverride::NoOverride,
        )?
        .send()
        .await?
        .service_error_for_status()
        .await?
        .json()
        .await
        .map_err(Into::into)
    }

    #[tracing::instrument(skip(self), level=tracing::Level::TRACE)]
    pub(crate) async fn get_attachment_resumable_upload_url(
        &mut self,
        attachment_upload_form: &AttachmentUploadForm,
    ) -> Result<Url, ServiceError> {
        let mut request = self.request(
            Method::POST,
            Endpoint::Absolute(
                attachment_upload_form.signed_upload_location.clone(),
            ),
            HttpAuthOverride::Unidentified,
        )?;

        for (key, value) in &attachment_upload_form.headers {
            request = request.header(key, value);
        }
        request = request.header(CONTENT_LENGTH, "0");

        if attachment_upload_form.cdn == 2 {
            request = request.header(CONTENT_TYPE, "application/octet-stream");
        } else if attachment_upload_form.cdn == 3 {
            request = request
                .header("Upload-Defer-Length", "1")
                .header("Tus-Resumable", "1.0.0");
        } else {
            return Err(ServiceError::UnknownCdnVersion(
                attachment_upload_form.cdn,
            ));
        };

        Ok(request
            .send()
            .await?
            .error_for_status()?
            .headers()
            .get("location")
            .ok_or(ServiceError::InvalidFrame {
                reason: "missing location header in HTTP response",
            })?
            .to_str()
            .map_err(|_| ServiceError::InvalidFrame {
                reason: "invalid location header bytes in HTTP response",
            })?
            .parse()?)
    }

    #[tracing::instrument(skip(self))]
    async fn get_attachment_resume_info_cdn2(
        &mut self,
        resumable_url: &Url,
        content_length: u64,
    ) -> Result<ResumeInfo, ServiceError> {
        let response = self
            .request(
                Method::PUT,
                Endpoint::cdn_url(2, resumable_url),
                HttpAuthOverride::Unidentified,
            )?
            .header(CONTENT_RANGE, format!("bytes */{content_length}"))
            .send()
            .await?
            .error_for_status()?;

        let status = response.status();

        if status.is_success() {
            Ok(ResumeInfo {
                content_range: None,
                content_start: content_length,
            })
        } else if status == StatusCode::PERMANENT_REDIRECT {
            let offset =
                match response.headers().get(RANGE) {
                    Some(range) => range
                        .to_str()
                        .map_err(|_| ServiceError::InvalidFrame {
                            reason: "invalid format for Range HTTP header",
                        })?
                        .split('-')
                        .nth(1)
                        .ok_or(ServiceError::InvalidFrame {
                            reason:
                                "invalid value format for Range HTTP header",
                        })?
                        .parse::<u64>()
                        .map_err(|_| ServiceError::InvalidFrame {
                            reason:
                                "invalid number format for Range HTTP header",
                        })?
                        + 1,
                    None => 0,
                };

            Ok(ResumeInfo {
                content_range: Some(format!(
                    "bytes {}-{}/{}",
                    offset,
                    content_length - 1,
                    content_length
                )),
                content_start: offset,
            })
        } else {
            Err(ServiceError::InvalidFrame {
                reason: "failed to get resumable upload data from CDN2",
            })
        }
    }

    #[tracing::instrument(skip(self))]
    async fn get_attachment_resume_info_cdn3(
        &mut self,
        resumable_url: &Url,
        headers: &HashMap<String, String>,
    ) -> Result<ResumeInfo, ServiceError> {
        let mut request = self
            .request(
                Method::HEAD,
                Endpoint::cdn_url(3, resumable_url),
                HttpAuthOverride::Unidentified,
            )?
            .header("Tus-Resumable", "1.0.0");

        for (key, value) in headers {
            request = request.header(key, value);
        }

        let response = request.send().await?.error_for_status()?;

        let upload_offset = response
            .headers()
            .get("upload-offset")
            .ok_or(ServiceError::InvalidFrame {
                reason: "no Upload-Offset header in response",
            })?
            .to_str()
            .map_err(|_| ServiceError::InvalidFrame {
                reason: "invalid upload-offset header bytes in HTTP response",
            })?
            .parse()
            .map_err(|_| ServiceError::InvalidFrame {
                reason: "invalid integer value for Upload-Offset header",
            })?;

        Ok(ResumeInfo {
            content_range: None,
            content_start: upload_offset,
        })
    }

    /// Upload attachment
    ///
    /// Returns attachment ID and the attachment digest
    #[tracing::instrument(skip(self, headers, content))]
    pub(crate) async fn upload_attachment_v4(
        &mut self,
        cdn_id: u32,
        resumable_url: &Url,
        content_length: u64,
        headers: HashMap<String, String>,
        content: impl std::io::Read + std::io::Seek + Send,
    ) -> Result<AttachmentDigest, ServiceError> {
        if cdn_id == 2 {
            self.upload_to_cdn2(resumable_url, content_length, content)
                .await
        } else {
            self.upload_to_cdn3(
                resumable_url,
                &headers,
                content_length,
                content,
            )
            .await
        }
    }

    #[tracing::instrument(skip(self, upload_attributes, reader))]
    pub async fn upload_to_cdn0(
        &mut self,
        path: &str,
        upload_attributes: AttachmentV2UploadAttributes,
        filename: String,
        mut reader: impl Read + Send,
    ) -> Result<(), ServiceError> {
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .expect("infallible Read instance");

        // Amazon S3 expects multipart fields in a very specific order
        // DO NOT CHANGE THIS (or do it, but feel the wrath of the gods)
        let form = reqwest::multipart::Form::new()
            .text("acl", upload_attributes.acl)
            .text("key", upload_attributes.key)
            .text("policy", upload_attributes.policy)
            .text("Content-Type", "application/octet-stream")
            .text("x-amz-algorithm", upload_attributes.algorithm)
            .text("x-amz-credential", upload_attributes.credential)
            .text("x-amz-date", upload_attributes.date)
            .text("x-amz-signature", upload_attributes.signature)
            .part(
                "file",
                Part::stream(buf)
                    .mime_str("application/octet-stream")?
                    .file_name(filename),
            );

        let response = self
            .request(
                Method::POST,
                Endpoint::cdn(0, path),
                HttpAuthOverride::NoOverride,
            )?
            .multipart(form)
            .send()
            .await?
            .error_for_status()?;

        debug!("HyperPushService::PUT response: {:?}", response);

        Ok(())
    }

    #[tracing::instrument(skip(self, content))]
    async fn upload_to_cdn2(
        &mut self,
        resumable_url: &Url,
        content_length: u64,
        mut content: impl std::io::Read + std::io::Seek + Send,
    ) -> Result<AttachmentDigest, ServiceError> {
        let resume_info = self
            .get_attachment_resume_info_cdn2(resumable_url, content_length)
            .await?;

        let mut digester =
            crate::digeststream::DigestingReader::new(&mut content);

        let mut buf = Vec::new();
        digester.read_to_end(&mut buf)?;

        trace!("digested content");

        let mut request = self.request(
            Method::PUT,
            Endpoint::cdn_url(2, resumable_url),
            HttpAuthOverride::Unidentified,
        )?;

        if let Some(content_range) = resume_info.content_range {
            request = request.header(CONTENT_RANGE, content_range);
        }

        request.body(buf).send().await?.error_for_status()?;

        Ok(AttachmentDigest {
            digest: digester.finalize(),
            incremental_digest: None,
            incremental_mac_chunk_size: 0,
        })
    }

    #[tracing::instrument(skip(self, content))]
    async fn upload_to_cdn3(
        &mut self,
        resumable_url: &Url,
        headers: &HashMap<String, String>,
        content_length: u64,
        mut content: impl std::io::Read + std::io::Seek + Send,
    ) -> Result<AttachmentDigest, ServiceError> {
        let resume_info = self
            .get_attachment_resume_info_cdn3(resumable_url, headers)
            .await?;

        trace!(?resume_info, "got resume info");

        if resume_info.content_start == content_length {
            let mut digester =
                crate::digeststream::DigestingReader::new(&mut content);
            let mut buf = Vec::new();
            digester.read_to_end(&mut buf)?;
            return Ok(AttachmentDigest {
                digest: digester.finalize(),
                incremental_digest: None,
                incremental_mac_chunk_size: 0,
            });
        }

        let mut digester =
            crate::digeststream::DigestingReader::new(&mut content);
        digester.seek(SeekFrom::Start(resume_info.content_start))?;

        let mut buf = Vec::new();
        digester.read_to_end(&mut buf)?;

        trace!("digested content");

        let mut request = self.request(
            Method::PATCH,
            Endpoint::cdn(3, resumable_url.path()),
            HttpAuthOverride::Unidentified,
        )?;

        for (key, value) in headers {
            request = request.header(key, value);
        }

        request
            .header("Tus-Resumable", "1.0.0")
            .header("Upload-Offset", resume_info.content_start)
            .header("Upload-Length", buf.len())
            .header(CONTENT_TYPE, "application/offset+octet-stream")
            .body(buf)
            .send()
            .await?
            .error_for_status()?;

        trace!("attachment uploaded");

        Ok(AttachmentDigest {
            digest: digester.finalize(),
            incremental_digest: None,
            incremental_mac_chunk_size: 0,
        })
    }
}
