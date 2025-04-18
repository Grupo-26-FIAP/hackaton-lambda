import { createHmac } from 'crypto';

export const getAwsSecretHash = (email) => {
  const CLIENT_SECRET = process.env.AWS_COGNITO_CLIENT_SECRET;
  const CLIENT_ID = process.env.AWS_COGNITO_CLIENT_ID;

  const hasher = createHmac('sha256', CLIENT_SECRET);
  hasher.update(`${email}${CLIENT_ID}`);
  const secretHash = hasher.digest('base64');

  return secretHash;
}