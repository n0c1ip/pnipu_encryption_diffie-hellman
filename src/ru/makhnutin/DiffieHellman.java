package ru.makhnutin;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/**
 *  Эмуляция алгоритма Диффи — Хеллмана с последующим шифрованием файлов алгоритмом AES
  */
public class DiffieHellman {

	private static final String AES_ALG = "AES";
	private static final int BIT_LENGTH = 128;
	// Заранее известные значения для участников P1 и P2
	private static final BigInteger q = new BigInteger("9876430584221297");
	private static final BigInteger n = new BigInteger("9876430584221323");

	public static void main(String[] args) throws Exception {

		BigInteger x,y,A,B,Ky,Kx;
		Random randomGenerator = new Random();

		System.out.printf("Заранее известные числа q и n %d и %d соответственно \n", q,n);

		x = BigInteger.probablePrime(BIT_LENGTH,randomGenerator);
		System.out.println("Участник P1 генерирует псевдослучайное простое число x = " + x);

		A=q.modPow(x, n);
		System.out.println("Участник P1 вычисляет значение q^x mod n и посылает участнику P2, A = " + A);

		y = BigInteger.probablePrime(BIT_LENGTH,randomGenerator);
		System.out.println("Участник P2 генерирует псевдослучайное простое число y = " + y);

		B=q.modPow(y, n);
		System.out.println("Участник P2 вычисляет значение q^y mod n и посылает участнику P1, B = " + B);

		Kx = B.modPow(x,n);
		System.out.println("Участник P1 на основе полученного значения B вычисляет секретный ключ Kx = B^x mod n = " + Kx);

		Ky = A.modPow(y,n);
		System.out.println("Участник P2 на основе полученного значения A вычисляет секретный ключ Ky = A^x mod n = " + Ky);

		// Используем полученное значение как ключ для алгоритма AES
		byte[] key = Kx.toString().getBytes();
		SecretKeySpec secret = new SecretKeySpec(Arrays.copyOf(key,  16), AES_ALG);
		Cipher cipher = Cipher.getInstance(AES_ALG);

		// Шифруем и дешфируем текстовый файл
		fileProcessor(cipher, Cipher.ENCRYPT_MODE, "source_text.txt", "encrypted_text.txt", secret);
		fileProcessor(cipher, Cipher.DECRYPT_MODE, "encrypted_text.txt", "decrypted_text.txt", secret);

		// Шифруем и дешфируем файл с изображением
		fileProcessor(cipher, Cipher.ENCRYPT_MODE, "source_pict.jpeg", "encrypted_pict.jpeg", secret);
		fileProcessor(cipher, Cipher.DECRYPT_MODE, "encrypted_pict.jpeg", "decrypted_pict.jpeg", secret);
	}

	/**
	 *
	 * @param cipher экземпляр класса шифрования с заранее выбранным алгоритмом
	 * @param cipherMode использование данной функции, для шифрования Cipher.ENCRYPT_MODE, дешифрование Cipher.DECRYPT_MODE
	 * @param inFile путь входящего файла
	 * @param outFile путь исходного файла
	 * @param secretKey секретный ключ
	 * @throws Exception
	 */
	static void fileProcessor(Cipher cipher, int cipherMode, String inFile,String outFile, SecretKey secretKey) throws Exception {

		if (cipherMode == Cipher.ENCRYPT_MODE) {
			System.out.println("Зашифрован файл: " + inFile + ", выходной файл: " + outFile);
		} else if (cipherMode == Cipher.DECRYPT_MODE) {
			System.out.println("Расшифрован файл: " + inFile + ", выходной файл: " + outFile);
		}
		File inputFile = new File(inFile);
		File outputFile = new File(outFile);
		cipher.init(cipherMode, secretKey);
		FileInputStream inputStream = new FileInputStream(inputFile);
		byte[] inputBytes = new byte[(int) inputFile.length()];
		inputStream.read(inputBytes);
		byte[] outputBytes = cipher.doFinal(inputBytes);
		FileOutputStream outputStream = new FileOutputStream(outputFile);
		outputStream.write(outputBytes);
		inputStream.close();
		outputStream.close();

	}





}
