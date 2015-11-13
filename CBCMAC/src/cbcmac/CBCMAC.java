package cbcmac;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import java.util.Scanner;

public class CBCMAC {

    /* Метод для получения имитовставки CBCMAC для текстового сообщения. */
    public byte[] getCBCMac(String message) throws Exception {

        // Создаем генератор ключей для DES
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        kg.init(56); // 56 - размер ключа. Фиксирован для DES
        SecretKey key1 = kg.generateKey();
        SecretKey key2 = kg.generateKey();

        // Создаем будущую имитовставку
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(key1);

        // Переводим строку в байты
        byte[] dataBytes = message.getBytes();

        // Добавляем байты в имитовставку, обрабатывая
        for(byte bite: dataBytes) {
            mac.update(bite);
        }
        byte[] macbytes = mac.doFinal();

        // Переходим к CBCMac: дополнительно кодируем получившуюся имитовставку вторым ключом
        DesEncrypter encrypter = new DesEncrypter(key2);
        macbytes = encrypter.encrypt(macbytes);

        return macbytes;
    }

    public static void main(String[] args) throws Exception {

        System.out.println("Пример сообщения:");

        Scanner in = new Scanner(System.in);
        String message = in.nextLine();

        CBCMAC myExample = new CBCMAC();
        byte[] myMac = myExample.getCBCMac(message);

        System.out.println();
        System.out.println("Результат кодирования:");
        System.out.print(myMac.toString());


    }
}
