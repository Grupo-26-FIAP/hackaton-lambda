import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

const client = jwksClient({
  jwksUri: "adicionar a poolId",
});

const getKey = (header, callback) => {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err, null);
    } else {
      const signingKey = key.getPublicKey();
      callback(null, signingKey);
    }
  });
};

export const handler = async (event) => {
  try {
    console.log(event);

    const authorizationHeader = event.headers.authorization;
    if (!authorizationHeader) {
      throw new Error("Cabeçalho de autorização ausente");
    }

    const token = authorizationHeader.split(" ")[1];
    if (!token) {
      throw new Error("Token não fornecido");
    }

    console.log({ tokencapturado: token });

    // Verifica e decodifica o token usando as chaves públicas do Cognito
    const decodedToken = await new Promise((resolve, reject) => {
      jwt.verify(token, getKey, { algorithms: ["RS256"] }, (err, decoded) => {
        if (err) {
          reject(err);
        } else {
          resolve(decoded);
        }
      });
    });

    console.log({ decodedToken });

    if (!decodedToken) {
      throw new Error("Token inválido");
    }

    // Verifique claims adicionais, como expiração ou audience
    const currentTime = Math.floor(Date.now() / 1000);
    if (decodedToken.exp < currentTime) {
      throw new Error("Token expirado");
    }

    // Token válido, permitir acesso
    return generatePolicy("Allow", event.routeArn, decodedToken.sub);
  } catch (error) {
    console.error("Erro ao validar token:", error.message);
    return generatePolicy("Deny", event.routeArn, "unauthorized");
  }
};

// Função auxiliar para gerar a política de autorização
const generatePolicy = (effect, resource, principalId) => {
  return {
    principalId: principalId,
    policyDocument: {
      Version: "2012-10-17",
      Statement: [
        {
          Action: "execute-api:Invoke",
          Effect: effect,
          Resource: resource,
        },
      ],
    },
  };
};