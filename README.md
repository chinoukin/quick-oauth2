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