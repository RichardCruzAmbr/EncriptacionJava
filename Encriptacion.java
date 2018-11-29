package mx.com.rcambrosio.prueba.controller;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Metodos de encriptacion y desencriptacion de cadena string
 * @author Ricardo Cruz Ambrosio
 * @version 1.0
 *
 */
public class Encriptacion {
	public final static String KEY = "4NTR4xXx1R1CH4RD"; //llave
    public final static String IV = "0123456789ABCDEF"; // vector de inicialización
    
	/**
	 * Metodo para generar cadena encriptada
	 * 
	 * @param texto // String
	 * @param id // Integer
	 * 
	 * @return BytesEncriptados // byte[]
	 *  
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] encriptar(String texto, long idDispositivo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		String mensajeCifrado = texto + idDispositivo; // Concatenamos los parametros a encriptar
	    byte[] BytesEncriptados = null;
		 try{
			 byte[] key = (KEY).getBytes("UTF-8");
			 key = Arrays.copyOf(key, 32); // Asignamos tamaño de la llave
			 Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Instanciamos el algoritmo de cifrado que utilizaremos
			 SecretKeySpec llave = new SecretKeySpec(key, "AES"); // Instanciamos la llave a utilizar 
			 cipher.init(Cipher.ENCRYPT_MODE, llave, new IvParameterSpec(IV.getBytes("UTF-8"))); // Inicializa este cifrado con la clave pública del certificado dado.
			 ByteArrayOutputStream out = new ByteArrayOutputStream();
			 try (CipherOutputStream cipherOutputStream = new CipherOutputStream(out, cipher)) {
		            cipherOutputStream.write(mensajeCifrado.getBytes()); // ciframos la cadena de texto
		            cipherOutputStream.flush();
		     }
		     BytesEncriptados = out.toByteArray();
		 }catch(IOException ex){
			 ex.getStackTrace();
		 }
		 return BytesEncriptados;
    }
	
	/**
	 * Metodo para desencriptar cadena
	 * 
	 * @param textoEncriptado // byte[]
	 * @return cadena de texto desencriptada // String
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws UnsupportedEncodingException
	 */
	public String desencriptar(byte[] textoEncriptado) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
		byte[] key = (KEY).getBytes("UTF-8");
		key = Arrays.copyOf(key, 32); // Asignamos tamaño de la llave
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Instanciamos el algoritmo de cifrado que utilizaremos
		SecretKeySpec llave = new SecretKeySpec(key, "AES");  // Instanciamos la llave a utilizar 
		cipher.init(Cipher.DECRYPT_MODE, llave,new IvParameterSpec(IV.getBytes("UTF-8"))); // Inicializa este cifrado con la clave pública del certificado dado.
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out = new ByteArrayOutputStream();
        ByteArrayInputStream inStream = new ByteArrayInputStream(textoEncriptado); // Desencriptamos el token
        CipherInputStream cipherInputStream = new CipherInputStream(inStream, cipher);
        byte[] buf = new byte[1024];
        int bytesRead;
        try {
            while ((bytesRead = cipherInputStream.read(buf)) >= 0) {
                out.write(buf, 0, bytesRead);
            }
        } catch (IOException ex) {
            ex.getStackTrace();
        }       
        return new String(out.toByteArray());
    }
}
