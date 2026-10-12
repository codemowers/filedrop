'use strict';
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { Readable } = require('stream');

const BUCKET = process.env.S3_BUCKET || 'codemowers-agent-system.filedrop';
const ENDPOINT = process.env.S3_ENDPOINT || 'http://minio.minio:9000';
const ACCESS_KEY = process.env.S3_ACCESS_KEY;
const SECRET_KEY = process.env.S3_SECRET_KEY;
const REGION = process.env.S3_REGION || 'ee-lte-1';

let s3;

function getS3() {
  if (!s3) {
    s3 = new S3Client({
      endpoint: ENDPOINT,
      region: REGION,
      credentials: {
        accessKeyId: ACCESS_KEY,
        secretAccessKey: SECRET_KEY,
      },
      forcePathStyle: true,
    });
  }
  return s3;
}

async function uploadToS3(key, buffer, contentType) {
  await getS3().send(new PutObjectCommand({
    Bucket: BUCKET,
    Key: key,
    Body: buffer,
    ContentType: contentType,
  }));
}

async function downloadFromS3(key, rangeHeader) {
  const params = { Bucket: BUCKET, Key: key };
  if (rangeHeader) params.Range = rangeHeader;
  const response = await getS3().send(new GetObjectCommand(params));
  // Body is a web ReadableStream in Node 18+; convert to Node stream
  if (response.Body && typeof response.Body.transformToWebStream === 'function') {
    return Readable.fromWeb(response.Body.transformToWebStream());
  }
  if (response.Body && response.Body.pipe) {
    return response.Body;
  }
  // Fallback: collect and wrap
  const bytes = await response.Body.transformToByteArray();
  return Readable.from(Buffer.from(bytes));
}

async function deleteFromS3(key) {
  await getS3().send(new DeleteObjectCommand({ Bucket: BUCKET, Key: key }));
}

module.exports = { uploadToS3, downloadFromS3, deleteFromS3 };
