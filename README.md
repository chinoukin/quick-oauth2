# quick-oauth2

## jvm参数：代理
-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=10808 -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=10808

## 非对称jwt
```
# 1. 生成JKS密钥库（包含私钥和自签名证书）
keytool -genkeypair \
  -alias jwt-key \
  -keyalg RSA \
  -keysize 2048 \
  -validity 365 \
  -keystore keystore.jks \
  -storetype JKS \
  -storepass 123456 \
  -keypass 123456 \
  -dname "CN=auth-server, OU=OAuth2, O=MyCompany, L=Beijing, ST=Beijing, C=CN"

# 2. 查看密钥库内容
keytool -list -v -keystore keystore.jks -storepass 123456

# 3. 导出公钥证书（给资源服务器用）
keytool -exportcert \
  -alias jwt-key \
  -keystore keystore.jks \
  -storepass 123456 \
  -file certificate.cer

# 4. 将证书转换为PEM格式
keytool -exportcert \
  -alias jwt-key \
  -keystore keystore.jks \
  -storepass 123456 \
  -rfc \
  -file public-key.pem
```

## 无状态auth-client
1.auth-client-stateless  
自定义jwt所使用的密钥(对称加密)并不是和auth-server相关的，生成的jwt只能用于auth-client-stateless服务。（第三方登录的token仅用于从resourceServer中获取用户信息，最终返回的都是自定义token）  
2.auth-client-stateless2  
自定义jwt所使用的密钥(非对称加密)和auth-server是同一个，生成的jwt能用于auth-resource和auth-client-stateless2服务。（第三方登录直接返回auth-server创建的token,本地登录返回自定义token）