package rsa;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Scanner;

/**
 * ЭЦП на базе RSA (класс RSA).
 * Использование ЭЦП двумя пользователями: создание ключей RSA, обмен публичными ключами, обмен кодированными сообщениями.
 *
 * Serpoletta, 2015.
 */

public class RSAUser {
    public String name;
    private RSA rsa;

    private BigInteger foreignPublicKey;
    private BigInteger foreignModulus;

    RSAUser() {
        this.name = "Аноним";
    }

    RSAUser(String name) {
        this.name = name;
    }

    public void createKeys(int N) {
        this.rsa = new RSA(N);
    }


    // Методы для обмена ключами
    public BigInteger givesPublicKey() {
        return this.rsa.getPublicKey();
    }
    public BigInteger givesModulus() {
        return this.rsa.getModulus();
    }

    public void getsKeyModulus(BigInteger key, BigInteger mod) {
        this.foreignPublicKey = key;
        this.foreignModulus = mod;
    }

    // Метод для кодирования текстового сообщения по двум ключам
    public ArrayList<BigInteger> crypts(String message) {
        // Кодируем текст в список чисел
        ArrayList<BigInteger> number = this.rsa.stringToBigIntegerList(message);

        // Кодируем по двум ключам - появляется список кодов
        ArrayList<BigInteger> code = this.rsa.crypt(number,foreignPublicKey,foreignModulus);
        return code;
    }

    // Метод для декодирования текстового сообщения из списка кодов двумя ключами
    public String decrypts(ArrayList<BigInteger> code) { //принимаем список кодов
        // Декодируем по двум ключам
        ArrayList<BigInteger> number = this.rsa.decrypt(code,foreignPublicKey,foreignModulus);

        String message = this.rsa.bigIntegerListToString(number);
        return message;
    }


    public static void main(String[] args) {
        RSAUser Alisa = new RSAUser("Алиса");
        RSAUser Bob = new RSAUser("Боб");

        // Разная длина ключей, иначе возникает переполнение и появляются всяческие аномалии.
        Alisa.createKeys(1024);
        Bob.createKeys(512);

        // Обмен ключами
        Alisa.getsKeyModulus(Bob.givesPublicKey(), Bob.givesModulus());
        Bob.getsKeyModulus(Alisa.givesPublicKey(), Alisa.givesModulus());

        // Ввод сообщения Боба
        System.out.println("A message from Bob:");
        //String message = "Omnia vincit amor";
        Scanner in = new Scanner(System.in);
        String message = in.nextLine();

        // Кодирование сообщение, пересылка и декодирование его Алисой
        ArrayList<BigInteger> cryptedMessage = Bob.crypts(message);
        String decryptedMessage = Alisa.decrypts(cryptedMessage);
        System.out.println("The message Alisa reads:");
        System.out.println(decryptedMessage);
    }
}
