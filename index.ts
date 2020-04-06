import * as jose from "jose";

type JWMAttributes<T extends {}> = {
  id?: string;
  type?: string;
  body?: T;
  to?: string;
  from?: string;
  thread_id?: string;
  referent_id?: string;
  time_stamp?: Date;
  expiry?: Date;
  reply_url?: string;
  reply_to?: string;
};

const defaultHeader = {
  typ: "JWM"
};

const errorBool = (fn: () => void) => {
  try {
    fn();
    return true;
  } catch (err) {
    return false;
  }
};

const signAndSerialise = <T>(
  attrs: JWMAttributes<T>,
  key: jose.ProduceKeyInputWithNone,
  _protected?: object
) =>
  jose.JWS.sign(attrs, key, {
    ...defaultHeader,
    ..._protected
  });

const verifySigned = (
  jwm: string,
  key: jose.ConsumeKeyInputWithNone
): boolean => errorBool(() => jose.JWS.verify(jwm, key));

const encryptAndSerialise = <T>(
  attrs: JWMAttributes<T>,
  key: jose.ProduceKeyInput,
  _protected?: object
) =>
  jose.JWE.encrypt(JSON.stringify(attrs), key, {
    ...defaultHeader,
    ..._protected
  });
const decryptEncrypted = <T>(
  jwm: string,
  key: jose.ConsumeKeyInput
): JWMAttributes<T> => JSON.parse(jose.JWE.decrypt(jwm, key).toString());

jose.JWK.generate("EC").then(key => {
  const m = {
    id: "hello",
    body: {
      a: "there"
    }
  };
  const ser = signAndSerialise(m, key, {
    cty: "nuthin'"
  });

  console.log(ser);

  const enc = encryptAndSerialise(m, key, { a: "my header string" });
  console.log(enc);
  console.log(decryptEncrypted(enc, key));
  console.log(verifySigned(ser, jose.JWK.generateSync("EC")));
});
