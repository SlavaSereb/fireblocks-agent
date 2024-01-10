/**
 * This file was auto-generated by openapi-typescript.
 * Do not make direct changes to the file.
 */


export interface paths {
  "/messagesStatus": {
    /** Get updates on requested messages */
    post: {
      requestBody: {
        content: {
          "application/json": components["schemas"]["MessagesStatusRequest"];
        };
      };
      responses: {
        200: {
          content: {
            "application/json": components["schemas"]["MessagesStatusResponse"];
          };
        };
      };
    };
  };
  "/messagesToSign": {
    /** Sign Messages */
    post: {
      /** @description Messages to sign */
      requestBody: {
        content: {
          "application/json": components["schemas"]["MessagesRequest"];
        };
      };
      responses: {
        /** @description Messages Status */
        200: {
          content: {
            "application/json": components["schemas"]["MessagesStatusResponse"];
          };
        };
        default: components["schemas"]["Error"];
      };
    };
  };
}

export type webhooks = Record<string, never>;

export interface components {
  schemas: {
    MessagesStatusRequest: {
      msgIds: number[];
    };
    MessagesStatusResponse: {
      messages: components["schemas"]["MessageStatus"][];
    };
    MessagesRequest: {
      messages: components["schemas"]["MessageEnvelope"][];
    };
    MessageEnvelope: {
      /** @example 425878000014 */
      msgId: number;
      type: components["schemas"]["TxType"];
      message: components["schemas"]["Message"];
      /**
       * Format: string
       * @description Original message payload
       */
      payload: string;
    };
    MessageStatus: {
      type: components["schemas"]["TxType"];
      /** @example 425878000014 */
      msgId: number;
      requestId: string;
      /**
       * @example SIGNED
       * @enum {string}
       */
      status: "PENDING_SIGN" | "SIGNED" | "FAILED";
      errorMessage?: string;
      signedPayload?: string;
      /** @description Original message payload */
      payload: string;
    };
    /**
     * @example EXTERNAL_KEY_PROOF_OF_OWNERSHIP
     * @enum {string}
     */
    TxType: "EXTERNAL_KEY_PROOF_OF_OWNERSHIP" | "TX";
    /**
     * @description algorithm to sign with
     * @example ECDSA_SECP256K1
     * @enum {string}
     */
    Algorithm: "ECDSA_SECP256K1" | "EDDSA_ED25519";
    Message: {
      /**
       * Format: uuid
       * @example ea7d0d9a-6a10-4288-9b91-da8fb0b149f2
       */
      tenantId: string;
      /** @example 1704122262 */
      timestamp: number;
      /** @example 1 */
      version: number;
      /** Format: uuid */
      fbKeyId: string;
      /**
       * Format: uuid
       * @example b015f35e-5d44-4d68-a0df-a1c625255abc
       */
      requestId: string;
      /** @example 70721651-a7f3-42f6-a984-6e058269495f */
      externalKeyId: string;
      algorithm: components["schemas"]["Algorithm"];
      /**
       * @description The string to sign
       * @example 3de97a18822d06fd19bea82522917c634c134a13ace2b887cf12e37dfd343d30
       */
      data: string;
    };
    Error: {
      message: string;
    };
  };
  responses: never;
  parameters: never;
  requestBodies: never;
  headers: never;
  pathItems: never;
}

export type $defs = Record<string, never>;

export type external = Record<string, never>;

export type operations = Record<string, never>;
