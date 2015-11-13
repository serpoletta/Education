package rsa;


/*
    RSA для простейшей ЭЦП на его базе. Java.

    RSA: создание ключей, кодирование числа, декодирование числа.
    RSA для ЭЦП: кодирование набора чисел двумя ключами, декодирование набора чисел двумя ключами.
    Вспомогательные методы: bigIntegerListToString, stringToBigIntegerList.

    Serpoletta, 2015.
*/


import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;
import java.util.ArrayList;

class RSA {
    public String message;
    int N; //количество бит для генерации RSA ключей 1024

    private BigInteger publicKey;
    private BigInteger privateKey;
    private BigInteger modulus;

    // Сеттеры, геттеры
    public BigInteger getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(BigInteger publicKey) {
        this.publicKey = publicKey;
    }

    public BigInteger getModulus() {
        return modulus;
    }
    private BigInteger getPrivateKey() {
        return privateKey;
    }

    // Генерация ключей
    public void createKeys() {
        final SecureRandom random = new SecureRandom();
        final BigInteger one = new BigInteger("1");

        // Создаем простые числа p и q
        BigInteger p = BigInteger.probablePrime(N / 2, random);
        BigInteger q = BigInteger.probablePrime(N / 2, random);

        modulus = p.multiply(q);

        // Вычисляем функцию Эйлера
        BigInteger p1 = p.subtract(one);
        BigInteger q1 = q.subtract(one);
        BigInteger phi = p1.multiply(q1);

        // Открытый ключ
        // Находим число меньшее, чем значение функции Эйлера, взаимно простое с n

        setPublicKey(phi);
        while (!((getPublicKey().compareTo(phi) == -1) && (getPublicKey().gcd(getModulus()).equals(one)))) {
            setPublicKey(BigInteger.probablePrime(N / 2, random));
        }

        // Приватный ключ
        privateKey = getPublicKey().modInverse(phi);

    }

    // Простое кодирование числа
    public BigInteger crypt(BigInteger m) {

        return m.modPow(getPublicKey(), getModulus());
    }

    public ArrayList<BigInteger> crypt(ArrayList<BigInteger> m, BigInteger foreignPublicKey, BigInteger foreignModulus) {

        ArrayList<BigInteger> code = new ArrayList<BigInteger>();
        for (BigInteger bite: m) {
            code.add((bite.modPow(getPrivateKey(), getModulus())).modPow(foreignPublicKey, foreignModulus));
        }
        return code;

    }

    // Простое декодирование числа
    public BigInteger decrypt(BigInteger code) {
        return code.modPow(getPrivateKey(), getModulus());
    }

    // Декодирование из списка кодов по двум ключам
    public ArrayList<BigInteger> decrypt(ArrayList<BigInteger> code, BigInteger foreignPublicKey, BigInteger foreignModulus) {

        ArrayList<BigInteger> m = new ArrayList<BigInteger>();
        for (BigInteger bite: code) {
            m.add((bite.modPow(getPrivateKey(), getModulus())).modPow(foreignPublicKey, foreignModulus));
        }
        return m;
    }

    // Разбиение сообщения на список чисел
    public ArrayList<BigInteger> stringToBigIntegerList (String s) {

        ArrayList<BigInteger> code = new ArrayList<BigInteger>();

        byte[] tmp = s.getBytes();

        for (int i=0;i<tmp.length;i++) {
            //System.out.println(tmp[i]);
            BigInteger bite = new BigInteger(String.valueOf(tmp[i]));
            code.add(bite);
        }
        return code;

    }

    // Сбор сообщения из списка чисел
    public String bigIntegerListToString (ArrayList<BigInteger> list) {
        String s = new String();

        for (BigInteger bi: list) {
            //System.out.println(bi);
            String bite = new String(bi.toByteArray());
            s += bite;
        }
        return s;
    }


    RSA() {
        this.N = 1024;
        this.createKeys();

    }
    RSA(int N) {
        this.N = N;
        this.createKeys();
    }

/*  Использование базового RSA
    public static void main(String[] args) {

		RSA rsa = new RSA();

		System.out.println("The message:");
		Scanner in = new Scanner(System.in);
		String message = in.nextLine();

		BigInteger mes = new BigInteger(message.getBytes());

		BigInteger cr_mes = rsa.crypt(mes);
		String decr_mes = new String(rsa.decrypt(cr_mes).toByteArray());
		System.out.println(decr_mes);

    }
*/

}
