import {
    AuthenticationDetails,
    CognitoUser,
    CognitoUserPool,
  } from 'amazon-cognito-identity-js';
  export const handler = async (event) => {
   const { email, password } = JSON.parse(event.body);
  
    const userPool = new CognitoUserPool({
      UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID,
      ClientId: process.env.AWS_COGNITO_CLIENT_ID,
    });
    const authenticationDetails = new AuthenticationDetails({
      Username: email,
      Password: password,
    });
    const userCognito = new CognitoUser({
      Username: email,
      Pool: userPool,
    });
    try {
      const response = await new Promise((resolve, reject) => {
        userCognito.authenticateUser(authenticationDetails, {
          onSuccess: (result) => {
            resolve({
              accessToken: result.getAccessToken().getJwtToken(),
              refreshToken: result.getRefreshToken().getToken(),
            });
          },
          onFailure: (err) => {
            reject(new Error(err.message || "Authentication failed"));
          },
        });
      });
      
      return {
        statusCode: 200,
        body: JSON.stringify(response),
      };
    } catch (error) {
      console.error({ error });
      return {
        statusCode: 401,
        body: JSON.stringify({
          message: "Authentication failed",
          error: error.message,
        }),
      };
    }
  };