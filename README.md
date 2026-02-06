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

## self-oauth前台快速启动
```
--窗口1
mvn clean install
cd self-oauth2/auth-server
mvn spring-boot:run -Dspring-boot.run.jvmArguments="-Xmx256m"
#mvn clean package
#java -Xmx256m -jar auth-server-1.0.0.jar
--窗口2
cd self-oauth2/auth-resource
mvn spring-boot:run -Dspring-boot.run.jvmArguments="-Xmx256m"
#mvn clean package
#java -Xmx256m -jar auth-resource-1.0.0.jar
--窗口3
#cd self-oauth2/auth-client
cd self-oauth2/auth-client-stateless2
mvn spring-boot:run -Dspring-boot.run.jvmArguments="-Xmx256m"
#mvn clean package
#java -Xmx256m -jar auth-client-stateless2-1.0.0.jar
```

## self-oauth后台快速启动
```
mvn clean install
cd self-oauth2/auth-server
mvn clean package
nohup java -Xmx256m -jar target/auth-server-1.0.0.jar > auth-server.log 2>&1 &

cd ../auth-resource
mvn clean package
nohup java -Xmx256m -jar target/auth-resource-1.0.0.jar > auth-resource.log 2>&1 &

cd ../auth-client-stateless2
mvn clean package
nohup java -Xmx256m -jar target/auth-client-stateless2-1.0.0.jar  > auth-client-stateless2.log 2>&1 &
```

## self-oauth后台快速启动2（不切换目录）
```
mvn clean install
mvn clean package -f self-oauth2/auth-server/pom.xml
mvn clean package -f self-oauth2/auth-resource/pom.xml
mvn clean package -f self-oauth2/auth-client-stateless2/pom.xml

nohup java -Xmx256m -jar self-oauth2/auth-server/target/auth-server-1.0.0.jar > auth-server.log 2>&1 &
nohup java -Xmx256m -jar self-oauth2/auth-resource/target/auth-resource-1.0.0.jar > auth-resource.log 2>&1 &
nohup java -Xmx256m -jar self-oauth2/auth-client-stateless2/target/auth-client-stateless2-1.0.0.jar  > auth-client-stateless2.log 2>&1 &
```