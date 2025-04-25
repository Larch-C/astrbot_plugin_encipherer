# 集合多种加解密工具的astrbot插件
  原encrypt-and-decrypt插件弃用，此为升级版。

# 指令使用说明
-`加解密帮助`: 获取插件使用说明。<br><br>
-`加密 <密钥> <明文>`: 使用用户输入的1-12位密钥对文本进行加密，得到`我`、`要`、`吃`、`饭`四个字组成的密文。例如：/<span title="指令">加密</span> <span title="密钥">ABC123</span> <span title="明文">你好</span><br><br>
-`解密 <密钥> <密文>`: 使用用户输入的1-12位密钥对文本进行解密，得到对应的明文。<br><br>
-`Base64编码 <文本>`: 对文本进行Base64编码。<br><br>
-`Base64解码 <文本>`: 对文本进行Base64解码。<br><br>
-`URL编码 <文本>`: 对文本进行URLencode编码。*URLEncode是将特殊字符转换为百分号编码的过程，确保浏览器和服务器间正确处理。它主要用于编码URL中的非ASCII字符和特殊字符，如空格变为%20，在HTTP请求提交参数时尤其重要。URL编码遵循特定规则，转换非ASCII字符并保持URL的兼容性和可处理性。* <br><br>
-`URL解码 <文本>`: 对文本进行URLencode解码。<br><br>
-`Pun编码 <文本>`: 对文本进行Punycode编码。*Punycode主要用于国际化域名（IDN），将Unicode字符串转换为ASCII兼容的编码（ACE）* <br><br>
-`Pun解码 <文本>`: 对文本进行Punycode解码。<br><br>
敬请期待

# 其他注意事项
-1、我要吃饭加解密的密钥必须使用由**数字、字母或其混合组成**的**6位**密钥，且**区分大小写**。<br><br>
-2、指令与操作的文本之间请用空格隔开，否则无法识别。<br><br>
-3、Punycode编码解码只对非ASCII字符进行了处理，以适应对中文域名的转换。<br><br>
-4、**插件功能仅做日常娱乐和交流分享，请勿用此插件的加密功能传播你所在的国家或地区规定的非法内容，违规使用导致所有后果均由使用者承担，开发者不对此负责。** <br><br>
The plug-in function is only for daily entertainment and communication and sharing, please do not use the encryption function of this plug-in to spread illegal content specified in your country or region, all consequences caused by illegal use are borne by the user, and the developer is not responsible for this.
