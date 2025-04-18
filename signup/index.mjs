import {
  CognitoUserAttribute,
  CognitoUserPool,
} from 'amazon-cognito-identity-js';
import AWS from 'aws-sdk';

export const handler = async (event) => {
  const { email, password } = JSON.parse(event.body);

  const userPool = new CognitoUserPool({
    UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
    ClientId: process.env.AWS_COGNITO_CLIENT_ID,
  });

  const attributesList = [
    new CognitoUserAttribute({ Name: 'email', Value: email }),
    new CognitoUserAttribute({ Name: 'password', Value: password }),
  ];
  try {
    const response = await new Promise((resolve, reject) => {
      userPool.signUp(email, password, attributesList, null, (err, result) => {
        if (err) {
          return reject(err);
        }
        resolve(result);
      });
    });
    
    const cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider();
    await cognitoIdentityServiceProvider.adminConfirmSignUp({
      UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
      Username: email,
    }).promise();


    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'User signed up and confirmed successfully' }),
    };

  } catch (error) {
    console.error({ error });
    return {
      statusCode: 500,
      body: JSON.stringify({
        message: "Failed to sign up",
        error: error.message,
      }),
    };
  }
};