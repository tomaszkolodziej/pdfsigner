1. Utworzyc keystore:
	keytool -genkey -alias tolean -keyalg RSA -keystore keystore.jks -keysize 2048

2. Utworzyc klucz:
	keytool -genkeypair -alias tkolodziej -keyalg RSA -keystore keystore.jks
	(jesli nie bedzie argumentu -keystore, to doda do aktualnego keystora)

3. Wyeksportowac certyfikat z keystora:
    keytool -export -alias tkolodziej -file tkolodziej.cer -keystore keystore.jks

Linki:
https://www.sslshopper.com/article-most-common-java-keytool-keystore-commands.html
https://docs.oracle.com/cd/E19798-01/821-1751/ghlgv/index.html

Budowanie projektu:
mvn install

<dependency>
	<groupId>com.tolean</groupId>
	<artifactId>pdfsigner</artifactId>
</dependency>