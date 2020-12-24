# Tutorials

## Radius Server
Radius нь **Remote Authentication Dial-In User Service** протокол юм. Энэхүү протокол нь Client (NAS /Network Access Server/) -ээс 1812 UDP портоор хүсэлтийг хүлээн авах бөгөөд хүсэлт нь Access-Request  төрлийн хүсэлт байна. Ирсэн Access-Request хүсэлтийг хүлээн авсах Radius server хүсэлтийг боловсруулж гурван төрлийн хариу буцаана. Үүнд
- Access - Reject
Access Reject нь хэрэглэгч идэвхгүй эсвэл хэрэглэгчийн мэдээлэл буруу байгааг илэрхийлнэ
- Access - Accept
Access Accept нь хэрэглэгчийн мэдээлэл зөв бөгөөд хэрэглэгчийг таних процесс дуусч зөвшөөрсөн болохыг илэрхийлнэ
- Access - Challenge
Access Challenge нь хэрэглэгчийг таних процесст нэмэлт мэдээлэл шаардлагатай байгаа тул нэмэлт мэдээлэл агуулсан Access - Request явуулах шаардлагатайг илэрхийлнэ

Radius протокол нь TCP шиг сервер лүү явуулсан Access - Request -ийн хариу гэх сегментчлэл байдаггүй учир серверт ирж байгаа хүсэлт болгон шинэ хүсэлт шиг харагдана. Иймээс хэрвээ 2FA тохируулж байгаа тохиолдолд Access-Challenge явуулахдаа нэмэлт талбар тохируулж тухайн талбарт Random string оруулж өгөх нь зохимжтой юм. Ингэснээр серверт ирсэн Access Request -ийн талбараас нэмэлт талбарыг хайж тухайн талбарт утга байгаа эсэхийг шалгаснаар тухайн хүсэлт эхний удаагых эсэхийг тодорхойлох боломжтой болох юм. Radius протоколд суурилсан олон төрлийн Application server байдагаас хамгийн түгээмэл Open Source нь FreeRadius юм.
# FreeRadius тохируулах нь
FreeRadius -г VPN холболтод зориулж тохируулсан учир энэхүү материалд зөвхөн хэрхэн NAS Client -аас Token асуух болон хэрэглэгчийг Active Directory -с шалгах талаар гарах болно.
FreeRadius серверийн тохиргоо нь ерөнхийдөө 3 төрлөөс бүрдэх юм. Үүнд:
- Virtual Server -ийн тохиргоо
- Client -ийн тохиргоо
- Module -ийн тохиргоо

гэх тохиргоогоос бүрдэх юм.
## Clients.conf
clients.conf тохиргооны файл нь Bracket Style -тай бөгөөд энд Radius Server -т холбогдох NAS client -ийн тохиргоо байрлах юм. NAS Client -ийн тохиргоонд IP хаяг, протокол (UDP/TCP), NAS Client -ийн Radius Server -тэй холболт тогтооход шаардлагатай secret string гэх мэт тохиргоонууд орно. Жишээ тохиргоо

    client CISCOISE {
		ipaddr = 1.1.1.1
		proto = *
		secret = mysecret
		require_message_authenticator = no
		nas_type	 = other
		virtual_server = home1
		limit {
			max_connections = 16
			lifetime = 0
			idle_timeout = 30
		}
	}
 - ipaddr -нь холбогдон NAS client -ийн хаягыг зааж өгнө
- proto нь NAS client -ийн ашиглах протоколыг зааж өгнө
- secret нь холбогдох NAS Client болон Radius Server хоорондын authentication хийх secret string -ийг зааж өгнө
- require_message_authenticator нь NAS Client -аас хамаарч тавигдах бөгөөд энэ нь NAS client -аас HMAC-MD5 ашиглан hash -лж явуулсан integrity check хийх талбар юм
- nas_type нь ямар төрлийн NAS болохыг заах бөгөөд үүнд:
    - cisco
    - computone
    - livingstone
    - juniper
    - netserver
гэх мэт байдаг харин others байвал өөр төрлийн NAS Client болохыг илэрхийлнэ
- virtual_server нь Radius Server -ийн виртуал серверийг хэлэх ба уг NAS Client нь зөвхөн тухайн virtual server -т л холбогдох юм
- max_connections нь тухайн NAS client -аас хамгийн ихдээ хэдэн connection нэгэн зэрэг хүлээн авахыг тодорхойлно
- lifetime нь NAS Client TCP протокол ашиглан холбогдож байгаа тохиолдолд ашиглах бөгөөд өгөгдсөн тоон утгын дагуу X секунд хүлээгээд холболтыг устгах юм
- idle_timeout нь мөн адил TCP протокол ашиглан холбогдож байгаа үед ашиглагдах бөгөөд connection ирхэд зааж өгсөн секунд хүлээгэд хариу ирээгүй тохиолдолд холболтыг устгана
## Virtual Server -ын тохиргоо (sites-enabled/default)
Энэ тохиргоо нь radius server -ын үндсэн тохиргооны файлын дайректорид байрлах sites-available дайректори дотор байрлах бөгөөд sites-available -аас sites-enabled рүү link хийж идэвхжүүлнэ. (Үндсэн radius.conf дотор аль дайректоригоос уншихыг зааж өгсөн байдаг) Жишээ тохиргоо

    server default{
		listen {
			type = auth
			ipaddr = 2.2.2.2
			port = 0
			limit {
				max_connections = 16
				lifetime = 0
				idle_timeout = 30
			}
		}
		authorize {
			filter_username
			preprocess
			chap
			mschap
			digest
			eap {
				ok = return
			}
			if (LDAP-Group == "notoken") {
				if (&User-Password) {
					update control {
						Auth-Type := LDAP
					}
				}
				else {
					reject
				}
			}
			elsif (LDAP-Group == "token") {
				if (!State) {
					if (&User-Password) {
						update control {
							Auth-Type := LDAP2FA
						}
					}
					else {
						reject
					}
				}
				else {
					if (&User-Password) {
						update control {
							Auth-Type := pam
						}
					}
					else {
						reject
					}
				}
			}
		}
		authenticate {
			Auth-Type PAP {
				pap
			}
			Auth-Type CHAP {
				chap
			}
			Auth-Type MS-CHAP {
				mschap
			}
			mschap
			digest
			Auth-Type LDAP2FA {
				ldap
				if (ok) {
					update reply {
						State := '%{randstr: aaaaaaaaaaaaaaaa}'
						Reply-Message := "Please enter token"
					}
					challenge
					%{echo: '%{User-Password}'}
					pam
				}
			}
			Auth-Type LDAP {
				ldap
			}
			eap
			pam
		}
		preacct {
			preprocess
			acct_unique
		}
		accounting {
			detail
			exec
			attr_filter.accounting_response
		}
		session {
		}
		post-auth {
			update {
				&reply: += &session-state:
			}
			exec
			remove_reply_message_if_eap
			Post-Auth-Type REJECT {
				attr_filter.access_reject
				eap
				remove_reply_message_if_eap
			}
			Post-Auth-Type Challenge {
				update {
					Reply-Message += "Please enter token"
				}
			}
		}
		pre-proxy {
			attr_filter.pre-proxy
		}
		post-proxy {
			eap
		}
	}
- server default нь виртуал серверийн эхлэх бөгөөд default нь виртуал серверийн нэр юм. 
- listen хэсэг
    - type нь ямар төрлийн listener болохыг зааж өгнө. Үүнд auth, acct гэсэн 2 төрөл байдаг бөгөөд auth нь authentication, acct нь accounting утгыг илэрхийлнэ
    - ipaddr нь radius server -ийн хаяг байх бөгөөд уг listener нь зааж өгсөн хаяг дээр ажиллах юм
    - port нь аль порт дээр сонсохыг зааж өгнө. Хэрвээ 0 утгатай байвал linux RPC -д зааж өгсөн портын дагуу сонсох юм. (RPC -д RFC -ын дагуу 1812 UDP гэж зааж өгсөн байдаг.)
- authorize хэсэг. Уг хэсэг нь ирсэн хүсэлтийг боловсруулах module -уудын жагсаалтын хэсэг бөгөөд энд зааж өгсөн модулиуд нь заавал ажиллах ёстой биш харин NAS client аас ирсэн authentication protocol -г Authorize хэсгээс хайж зөвхөн authorize хэсэгт байгаа тохиолдолд ажиллах юм.
    - filter_username нь mods-enabled доторхи filter_username модуль ажилана. Default тохиргоогоор уг модуль нь NAS Client аас ирсэн хэрэглэгчийн username талбарыг шалгаж илүү тэмдэгт агуулагдаагүй эсэхийг баталгаажуулах security plugin юм
    - preprocess нь filter_username -тэй ижил модуль юм
    - chap буюу Challenge Handshake Authentication Protocol нь NAS Client аас хэрэглэгчийн танилтыг хийхэд ашиглах бөгөөд зөвхөн NAS client -аас ирсэн Access Request нь CHAP ашиглана гэсэн тохиолдолд ажиллана
   - mschap нь chap -ын Microsoft -н гаргасан хувилбар юм
   - digest нь NAS Client Radius server -ийн хоорондох traffic -т өөрчлөлт ороогүйг баталгаажуулах модуль
   - eap нь Extensible Authentication Protocol нь танилт хийх фреймворк юм (Дэлгэрэнгүй мэдээллийг wikipedia дээрээс уншина уу)
   - if & elsif 
дээрх authentication -д шаардлагатай модулиуд ажиллаж дууссаны дараа бүх filter давсан тохиолдолд хэрэглэгчийг authentication хийх бөгөөд манай тохиолдолд хэрэглэгчийг Active Directory дээрээс хайх тул ldap модулийг оруулж өгнө. Үүний тулд Auth-Type -ийг LDAP болгож өгснөөр authenticate хийхдээ FreeRadius -д нэмэлтээр суулгасан LDAP модулийг дуудаж ажиллана. Харин манай тохиолдолд VPN Хэрэглэгч нь хэрвээ тусгай group -д байвал Token асуух шаардлагатай тул тохиргооны хэсэгт token болон notoken групд хэрэглэгчийг байгаа эсэхийг шалгаж authentication модулийг сольж байгаа юм. Хэрвээ token групд байгаа тохиолдолд Auth-Type := LDAP2FA тохируулж өгснөөр LDAP2FA нэртэй authentication function -г ашиглах юм.дээрх authentication -д шаардлагатай модулиуд ажиллаж дууссаны дараа бүх filter давсан тохиолдолд хэрэглэгчийг authentication хийх бөгөөд энэ тохиолдолд хэрэглэгчийг Active Directory дээрээс хайх тул ldap модулийг оруулж өгнө. Үүний тулд Auth-Type -ийг LDAP болгож өгснөөр authenticate хийхдээ FreeRadius -д нэмэлтээр суулгасан LDAP модулийг дуудаж ажиллана. Гэхдээ VPN Хэрэглэгч нь хэрвээ token group -д байвал Token асуух шаардлагатай тул тохиргооны хэсэгт token болон notoken групд хэрэглэгчийг байгаа эсэхийг шалгаж authentication модулийг сольж байгаа юм. Хэрвээ token групд байгаа тохиолдолд Auth-Type := LDAP2FA тохируулж өгснөөр LDAP2FA нэртэй authentication function -г ашиглах юм.

```
     if (LDAP-Group == "notoken") {
     	if (&User-Password) {
     		update control {
     			Auth-Type := LDAP
     		}
     	}
     else {
     	reject
     }
     }
```

Ингээд хэрэглэгчийн байгаа групээс хамааран Authentication Type -ийг тохируулсаны дараа authenticate block -руу шилжих юм.

```
   authenticate {
 	    	Auth-Type LDAP2FA {
 		    	ldap
 			    if (ok) {
 				    update reply {
 					    State := '%{randstr: aaaaaaaaaaaaaaaa}'
   					Reply-Message := "Please enter token"
   				}
   				challenge
   				%{echo: '%{User-Password}'}
   				pam
   			}
   		}
   		Auth-Type LDAP {
  			ldap
   		}
   		eap
 	    	pam
 	    }
```

дээрхи тохиргооноос харвал LDAP2FA нь ирсэн request -ийн User-Password талбарыг Active Directory -оос шалгаж username,password зөв тохиолдолд NAS client руу challenge request явуулж token -г асууснаар pam authentication хийхээр тохируулагдсан байгаа
## PAM Authentication гэж юу вэ?
PAM буюу Pluggable Authentication Module нь Linux үйлдлийн системийн authentication хийх процессийг low-level authentication схемийг high-level application program interface -тэй холбож өгөх үүрэгтэй механизм юм. PAM -нь Unix, FreeBSD, Solaris болон macOS үйлдлийн системүүд дэмжин ажилладаг. Энэхүү механизмийг FeeRadius -д ашигласанаар хэрэглэгчийн танилтыг Active Directory дээр хийгдсэний дараа дахин баталгаажуулалтыг үйлдлийн систем дээр суусан Google Authenticator модультай холбох боломжтой болох юм. PAM -ийг тохируулахдаа pam-ldap package -ийг суулгаж дараах тохиргоог хийж өгөх шаардлагатай. Тохиргооны файл нь `/etc/pam.d/radiusd` байх бөгөөд зөвхөн энэ файл нь radius daemon -д хариу өгөх юм.

>>>
#%PAM-1.0

auth    required      pam_google_authenticator.so     debug user=root secret=/path/token/${USER} forward_pass

account required     pam_unix.so     no_pass_expiry debug
>>>

 - auth required нь authentication хийгдэхэд заавал шаардлагатайг илэрхийлнэ
 - pam_google_authenticator.so нь google-authenticator модулийн so файл буюу `Shared Object` windows -ийн `DLL` юм. SO файлыг бүтэн замаар нь эсвэл шууд файлын нэрээр зааж өгч болох бөгөөд  файлын нэрээр зааж өгсөн тохиолдолд тухайн үйлдлийн системийн төрлөөс хамааран өөр өөрсдийн defeault so path -с хайж уншина.
 - SO файлын араас option тохируулж болох бөгөөд энэ тохиолдолд user=root буюу тухайн процессийн user -ийг зааж өгнө
 - Үүний араас secret=/path/token/${USER} option -ийг тохируулж өгснөөр тухайн хэрэглэгчийн token файлыг зааж өгөх юм. Энэд ${USER} бол хувьсагч бөгөөд PAM нь ирсэн хүсэлтээс user хэсгийг авч ${USER} -ийн оронд бичиж тухайн файлыг уншиж хэрэглэгчийг баталгаажуулах юм.
# Token File
Хэрэглэгчийн token файл нь дотроо secret код болох 26 тэмдэгт мөн recovery токен болон timestamp уудыг агуулсан текст файл байна
# LDAP тохиргоо
LDAP -ийн default тохиргоонд дараах утгуудыг сольж мөн нэмж өгнө.

        server = '3.3.3.3'
        identity = 'distinguishedname'
        password = password
        base_dn = 'dc=domain,dc=local'
        clientIdentifier = "groupDistinguishedName"
        user {
            base_dn = "${..base_dn}"
            filter = "(&(sAMAccountName=%{%{Stripped-User-Name}:-%{User-Name}})(memberOf=${..clientIdentifier}))"
        }

- server - Active Directory  server -ийн IP хаягыг оруулж өгнө
- identity - LDAP модуль нь Active Directory -оос хэрэглэгчийг хайхдаа эхлээд **BIND** хийдэг бөгөөд энэ хувьсагчид **BIND** хийх Active Directory хэрэглэгчийн distinguishedName -ийг оруулж өгнө
- password **BIND** хийх хэрэглэгчийн нууц үгийг оруулж өгнө
- base_dn - хэрэглэгчийг хайх хайлтын үндэс буюу ихэнхи тохиолдолд DC location -ийг тохируулж өгнө /Жишээлбэл DC=test,DC=local/
- clientIdentifier - хэрэглэгчийг хайхад хэрэглэгдэх группын distinguishedName -ийг оруулж өгнө. /Жишээлбэл зөвхөн EMPLOYEE группд байгаа хэрэглэгчийг л нэвтрүүлэх бол CN=EMPLOYEE,OU=SomeCompany,DC=test,DC=local/
- base_dn - default value -г өөрийн **clientIdentifier** аар сольно /clientIdentifier нь хуьсагчийн нэр тул өөрийн хүссэн нэрийг оруулж болно/
- filter - Active Directory -оос хайлт хийх **LDAP QUERY** -нд зориулсан филтерийг тавьж өгөх бөгөөд дээрх жишээ тохиргооны хувьд хэрэглэгчийн sAMAccountName талбар нь FreeRadius -ийн username талбартай ижил байгаа бөгөөд clientIdentifier болох жишээ группын гишүүн хэрэглэгчийг хайх филтер юм

Ингээд дээрх бүх тохиргоог хийж дууссаны дараа **radiusd** сервисийг асааснаар сервер 1812/UDP порт дээр сонсож байх болно.
# Misc
- Active Directory -той холбоход SSL ашиглах бол ActiveDirectory -ийн сертификатыг FreeRadius -ийн тохиргооны root directory -д certs директорид оруулж өгнө
- Олон client холбох тохиолдолд тус тусд нь үүсгэх эсвэл сүлжээгээр нь тохируулж болно
- 

# Турших

Тохируулсан Radius сервер ээ туршихдаа client.conf -д зөвшөөрч өгсөн сүлжээ/компьютер дээрээс [test.pl](test.pl) түүлийг ашиглан шалгаж болно. 

test.pl дээр **host** болон **secret** үүдийг өөрийн тохируулсны дагуу солино. 
шаардлагатай сан суулгах

```
[root@e-office ~]# cpan Term::ReadPassword 
[root@e-office ~]# cpan Authen::Radius
```

```
[root@e-office ~]# ./test.pl
Enter username: munkhbold.a
Enter password:
server response type = Access-Challenge (11)
Enter otp: 771081
server response type = Access-Accept (2)

```
