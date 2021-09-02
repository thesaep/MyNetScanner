import scapy.all as scapy                              # Ağda önce arp requesti sonra broadcasti ve sonra da response'u almamızı sağlar.
import optparse

#1)arp_request          önce istek oluşturuyoruz
#2)broadcast            sonra oluşturduğumuz 10.0.2.1/24 isteğini yani bu iplerin kime ait olduğunu ve mac adresinin ne olduğunu sormak için broadcast yapıp tüm bilgisayarlara yolluyoruz.            
#3)response             ve sonra hedef makine ip'yi görüyor ve kendi mac adresini bize söylüyor.

def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i","--ipaddress", dest="ip_address",help="Enter IP Address")

    (user_input,arguments) = parse_object.parse_args()

    if not user_input.ip_address:
        print("Enter IP Address")

    return user_input

def scan_my_network(ip):
    arp_request_packet = scapy.ARP(pdst=ip)                   # pdst, ağ içinde hangi ip'lerin olduğunun sorgusunu yapar. Örn "10.0.2.1/24" şeklinde. Nmap, netdiscover gibi..
    #scapy.ls(scapy.ARP())                                    # scapy.ls'i çalıştırıp üstteki pdst'in ne işe yaradığını öğrenip onu seçtik.
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")   # dst, destination yani hedef makine MAC'ini öğrenmemizi sağlıyor. ff:ff, tüm mac adresleri için geçerli olduğu için değiştirmiyoruz.
    #scapy.ls(scapy.Ether())                                  # Yine aynı şekil bu sefer MAC adresi için scapy.ls çalıştırıp neyin ne olduğunu öğrenip üstte dst'yi kullandık
    combined_packet = broadcast_packet/arp_request_packet     #arp ve broadcast paketlerini tek paket halinde yollamamız gerekiyor bunun için scapy dilinde "/" işareti ile paketleri birleştirdik.
    (answered_list,unanswered_list) = scapy.srp(combined_packet,timeout=1) # Cevap verilen ve verilmeyen paketlerin hepsini gösterecek.Timeout ise verilmeyen cevapları bekleme geç için kullanıldı.
    answered_list.summary()    # summary argümanı hangi ip adreslerinin hangi mac adreslerini taşıdığını terminalde çok net bi şekilde ayrıştırıp göstermeyi sağlıyor yoksa çok karmaşık görünürdü.

user_ip_address = get_user_input()
scan_my_network(user_ip_address.ip_address)