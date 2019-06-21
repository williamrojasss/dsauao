package DSA;

import java.io.FileInputStream;
import java.io.*;
import java.math.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.Base64;
import java.util.Random;
import java.math.BigInteger;
/**
 *
 * @author William Rojas
 */
public class DSA {
    /**
     * @param args the command line arguments
     */
    public static void main(String [] args) throws NoSuchAlgorithmException, IOException {
        try
        {
        //Validar el no tener argumentos.
        if (args[0] == null);
        }
        catch (Exception e){
            System.out.println(DSA.mensajes("-h"));
            System.exit(0);
        }
        switch (args [0])
        {
            case "-h":
            System.out.println(DSA.mensajes("-h"));
            break;
            case "-key":
            GenerarLlaves(args [1]);
            break;
            case "-sign":{
                hash_sha1(args [1]);
                String Key = LeerkeyPri(args [2]);
                Firma(Key,args[3]);
            }
            break;
            case "-securitykey":
                switch (args [1]){
                    case "-h":
                    System.out.println(DSA.mensajes("-securitykey -h"));
                    break;
                    default:
                    SecurityDsaKeyGenerator(args[1]);
                    break;
                }
            break;
            case "-securitysign":
                switch (args [1]){
                    case "-h":
                       System.out.println(DSA.mensajes("-securitysign -h"));
                    break;
                    default:
                        // KeyFile = Nombre del archivo Llave privada.
                        String keyFile = args[1];
                        // msgFile = Archivo para hacerle firma digital.
                        String msgFile = args[2];
                        // sigFile = Nombre del archivo de la firma digital a crear.    
                        String sigFile = args[3];
                        String keyAlgo = "DSA";
                        String sigAlgo = "SHA1withDSA";
                        try {
                        PrivateKey priKey = SecurityreadPrivateKey(keyFile);
                        Securitysign(msgFile,sigFile,sigAlgo,priKey);
                        } catch (Exception e) {
                        System.out.println("Exception: "+e);
                        return;
                        }
                    break;    
                }
            break;
            case "-securityverify":
                switch (args [1]){
                    case "-h":
                        System.out.println(DSA.mensajes("-securityverify -h"));    
                    break;
                    default:
                    // KeyFile = Nombre del archivo llave publica.
                    String keyFile = args[1];
                    // msgFile = Archivo para comprobar firma digital.
                    String msgFile = args[2];
                    // sigFile = Nombre del archivo de la firma digital a comprobar.    
                    String sigFile = args[3];
                    try {
                    PublicKey pubKey = SecurityreadPublicKey(keyFile);
                    byte[] sign = SecurityreadSignature(sigFile);
                    SecurityVerify(pubKey, sign, msgFile);
                    }
                     catch (Exception e) {
                            System.out.println("Exception: "+e);
                            return;
                    }
                    break;
            }
            default:
            mensajes("-h");
            break;
    }
}
    public static String LeerkeyPri(String archivo) throws FileNotFoundException, IOException {
        String cadena;
        String c = "";
        FileReader f = new FileReader(archivo);
        BufferedReader b = new BufferedReader(f);
        while((cadena = b.readLine())!=null) {
            //System.out.println(cadena);
            c +=cadena;
        }
        b.close();
        return c;
    }
    public static void Firma(String keyPri, String input) throws IOException{
    String P = "13232376895198612407547930718267435757728527029623408872245156039757713029036368719146452186041204237350521785240337048752071462798273003935646236777459223";
    String Q = "857393771208094202104259627990318636601332086981";
    String G = "5421644057436475141609648488325705128047428394380474376834667300766108262613900542681289080713724597310673074119355136085795982097390670890367185141189796";
    BigInteger p = new BigInteger(P);
    BigInteger q = new BigInteger(Q);
    BigInteger g = new BigInteger(G);
    BigInteger k = new BigInteger(256, new Random());
    String encodedkeyPri = keyPri;    
    //System.out.println(encodedkeyPri);
    byte[] decodedkeyPri = Base64.getDecoder().decode(encodedkeyPri);
    String decodedkeyPriS = new String(decodedkeyPri);    
    System.out.println("decodedkeyPri "+decodedkeyPriS);
    BigInteger r = g.modPow(k,p);
    BigInteger x = new BigInteger(decodedkeyPriS);
    BigInteger mhash = hash_sha1(input);
    
    /*while (k.modInverse(i));
    BigInteger s2 = r.multiply(x);
    BigInteger s3 = mhash.add(s2);
    BigInteger s = s1.multiply(s3);
    System.out.println(s);
    */
    }
    public static void GenerarLlaves(String keyname) throws FileNotFoundException, IOException{
    String P = "13232376895198612407547930718267435757728527029623408872245156039757713029036368719146452186041204237350521785240337048752071462798273003935646236777459223";
    String Q = "857393771208094202104259627990318636601332086981";
    String G = "5421644057436475141609648488325705128047428394380474376834667300766108262613900542681289080713724597310673074119355136085795982097390670890367185141189796";
       
    BigInteger p = new BigInteger(P);
    BigInteger q = new BigInteger(Q);
    BigInteger g = new BigInteger(G);
    BigInteger h = g.modPow(q,p);
    BigInteger x;
    System.out.println("h ="+h);
    //((h.compareTo(BigInteger.ONE) == 1))
    do{   
    x = new BigInteger(256, new Random());
    }
    while (x.compareTo(p)==1);
    BigInteger y = g.modPow(x,p);   
    System.out.println("p ="+p);
    System.out.println("q ="+q);
    System.out.println("g ="+g);
    System.out.println("x ="+x);
    System.out.println("y ="+y);
    
    System.out.println("Verificacion de DSA : ");
    System.out.println("Tamaño de P? "+p.bitLength());
    System.out.println("P es primo? "+p.isProbablePrime(200));
    System.out.println("Q es primo? "+q.isProbablePrime(200));
    System.out.println("p-1 mod q == 0? "+p.subtract(BigInteger.ONE).mod(q));
    System.out.println("g**q mod p == 1? "+g.modPow(q,p));
        
    String keyPri = x.toString();
        System.out.println("keyPri "+keyPri);
    String encodedkeyPri = Base64.getEncoder().encodeToString(keyPri.getBytes());
        System.out.println("Base64keyPri "+encodedkeyPri);
    byte[] bytesKeypri = encodedkeyPri.getBytes();    
    String fl = keyname+".private";
    FileOutputStream out = new FileOutputStream(fl);
    out = new FileOutputStream(fl);        
    out.write(bytesKeypri);
    out.close();    
    /*byte[] decodedkeyPri = Base64.getDecoder().decode(encodedkeyPri);
        String decodedkeyPriS = new String(decodedkeyPri);    
        System.out.println("decodedkeyPri "+decodedkeyPriS);*/
    String keyPub = y.toString();
        System.out.println("keyPub  "+keyPub);
    String encodedkeyPub = Base64.getEncoder().encodeToString(keyPub.getBytes());
        System.out.println("Base64keyPub "+encodedkeyPub);
    String f2 = keyname+".public";
    out = new FileOutputStream(f2);    
    byte[] bytesKeypub = encodedkeyPub.getBytes();    
    out.write(bytesKeypub);
    out.close();    
    /*byte[] decodedkeyPub = Base64.getDecoder().decode(encodedkeyPub);
        String decodedkeyPubS = new String(decodedkeyPub);    
        System.out.println("decodedkeyPri "+decodedkeyPubS);*/
    }
    public static BigInteger hash_sha1(String input) throws FileNotFoundException, IOException{
    BigInteger hash = BigInteger.ZERO;
        try{
        MessageDigest md= MessageDigest.getInstance("SHA");
        try{
            InputStream mensaje = new FileInputStream(input);
            byte[] buffer = new byte[1];
            int caracter;
            caracter = mensaje.read(buffer);
            while( caracter != -1 ) {
            md.update(buffer);
            caracter = mensaje.read(buffer);
            }   
            mensaje.close();
            byte[] resumen = md.digest(); // Genera el resumen SHA-1
            hash = new BigInteger(resumen);
                        
            String m = "";
            for (int i = 0; i < resumen.length; i++)
            {
               m += Integer.toHexString((resumen[i] >> 4) & 0xf);
               m += Integer.toHexString(resumen[i] & 0xf);
            }
            System.out.println("Resumen SHA-1: " + m);
            }
         //lectura de los datos del fichero
         catch(java.io.FileNotFoundException fnfe) {}
         catch(java.io.IOException ioe) {}
      
      }   
      //declarar funciones resumen
      catch(java.security.NoSuchAlgorithmException nsae) {}
    return hash;
    }
    public static void SecurityDsaKeyGenerator(String keyname){
        int keySize = 1024;
        String algorithm = "DSA";
        try {
        SecuritygenKeyPair(keySize,keyname,algorithm);
        }catch (Exception e) {
        System.out.println("Exception: "+e);
        return;
        }
    }  
    public static void SecuritygenKeyPair(int keySize, String output,String algorithm) throws Exception {
      KeyPairGenerator kg = KeyPairGenerator.getInstance(algorithm);
      kg.initialize(keySize);
      KeyPair pair = kg.generateKeyPair();
      PrivateKey priKey = pair.getPrivate();
      PublicKey pubKey = pair.getPublic();
      String fl = output+".private";
      FileOutputStream out = new FileOutputStream(fl);
      // Codificando a Base64 llave privada
      byte[] ky = priKey.getEncoded();
      byte[] privateKeyPem = Base64.getEncoder().encode(ky);
      System.out.println();
      System.out.println("Info Llave Privada: ");
      System.out.println("Archivo = "+fl);
      System.out.println("Tamaño = "+ky.length);
      System.out.println("Formato = "+priKey.getFormat());        
      String privateKeyPemStr = new String(privateKeyPem);
      System.out.println("-----BEGIN PRIVATE KEY-----");
      int column = 0;
      for(int n = 0; n < privateKeyPemStr.length(); n ++) {
      System.out.print(privateKeyPemStr.charAt(n));
      column ++;
      if(column == 64) {
      System.out.println();
      column = 0;
      }
      }
      System.out.println("\n-----END PRIVATE KEY-----");
      out.write(ky);
      out.close();
     
      fl = "base64_"+output+".private";
      out = new FileOutputStream(fl);
      String b64PrivateKey = Base64.getEncoder().encodeToString(ky);
      //System.out.println(b64PublicKey);
      out.write(b64PrivateKey.getBytes());
      out.close();
      
      fl = output+".public";
      out = new FileOutputStream(fl);
      ky = pubKey.getEncoded();
      System.out.println();
      System.out.println("Info Llave Publica: ");
      System.out.println("Algoritmo = "+pubKey.getAlgorithm());
      System.out.println("Archivo = "+fl);
      System.out.println("Tamaño = "+ky.length);
      System.out.println("Formato = "+pubKey.getFormat());
      System.out.println("toString = "+pubKey.toString());
      byte[] publicKeyPem = Base64.getEncoder().encode(ky);
      String publicKeyPemStr = new String(publicKeyPem);
      System.out.println("-----BEGIN PUBLIC KEY-----");
      column = 0;
      for(int n = 0; n < publicKeyPemStr.length(); n ++) {
      System.out.print(publicKeyPemStr.charAt(n));
      column ++;
      if(column == 64) {
      System.out.println();
      column = 0;
      }
      }
      System.out.println("\n-----END PUBLIC KEY-----");
      out.write(ky);
      out.close();      

      fl = "base64_"+output+".public";
      out = new FileOutputStream(fl);
      String b64PublicKey = Base64.getEncoder().encodeToString(ky);
      //System.out.println(b64PublicKey);
      out.write(b64PublicKey.getBytes());
      out.close();
   }
    public static PrivateKey SecurityreadPrivateKey(String input) throws Exception {
      String algorithm = "DSA";
      KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
      FileInputStream priKeyStream = new FileInputStream(input);
      int priKeyLength = priKeyStream.available();
      byte[] priKeyBytes = new byte[priKeyLength];
      priKeyStream.read(priKeyBytes);
      priKeyStream.close();
      PKCS8EncodedKeySpec priKeySpec 
         = new PKCS8EncodedKeySpec(priKeyBytes);
      PrivateKey priKey = keyFactory.generatePrivate(priKeySpec);
      return priKey;
   }
    public static PublicKey SecurityreadPublicKey(String input) throws Exception {
      String algorithm = "DSA";
      FileInputStream pubKeyStream = new FileInputStream(input);
      int pubKeyLength = pubKeyStream.available();
      byte[] pubKeyBytes = new byte[pubKeyLength];
      pubKeyStream.read(pubKeyBytes);
      pubKeyStream.close();
      X509EncodedKeySpec pubKeySpec 
         = new X509EncodedKeySpec(pubKeyBytes);
      KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
      PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
      return pubKey;
   } 
    public static byte[] Securitysign(String input, String output,String algorithm, PrivateKey priKey) throws Exception {
      Signature sg = Signature.getInstance(algorithm);
      sg.initSign(priKey);
      FileInputStream in = new FileInputStream(input);
      int bufSize = 1024;
      byte[] buffer = new byte[bufSize];
      int n = in.read(buffer,0,bufSize);
      int count = 0;
      while (n!=-1) {
         count += n;
         sg.update(buffer,0,n);
         n = in.read(buffer,0,bufSize);
      }
      in.close();
      String da = output+".sig";
      FileOutputStream out = new FileOutputStream(da);
      byte[] sign = sg.sign();
      out.write(sign);
      out.close();
      System.out.println();
      System.out.println("Informacion firma: ");
      System.out.println("Numero de bytes = "+sign.length);
      System.out.println("Nombre de archivo = "+da);
      System.out.println();
      return sign;
   }
    public static byte[] SecurityreadSignature(String sign) throws Exception {
      FileInputStream signStream = new FileInputStream(sign);
      int signLength = signStream.available();
      byte[] signBytes = new byte[signLength];
      signStream.read(signBytes);
      signStream.close();
      return  signBytes;
   }
    public static void SecurityVerify(PublicKey pubKey, byte[] sign, String input ) throws Exception {
      Signature sg = Signature.getInstance("DSA");
      sg.initVerify(pubKey);
      System.out.println();
      FileInputStream in = new FileInputStream(input);
      int bufSize = 1024;
      byte[] buffer = new byte[bufSize];
      int n = in.read(buffer,0,bufSize);
      int count = 0;
      while (n!=-1) {
         count += n;
         sg.update(buffer,0,n);
         n = in.read(buffer,0,bufSize);
      }
      in.close();
      boolean ok = sg.verify(sign);
      System.out.println("Informacion de Proceso de Verificacion: ");
      System.out.print("Resultado Verificacion = ");
      
      if (ok == true){
      System.out.println("!Verificación Correcta!");
      System.out.println("El archivo no ha sufrido modificaciones.\n");
      }
      else if (ok == false){
      System.out.println("¡Verificación de firma Incorrecta!");
      System.out.println("Existe la posibilidad de que el archivo ha sufrido modificaciones no autorizadas o no sea el archivo original.\n");    
      }
      
   }
    public static String mensajes(String args){
        String mensaje;
        mensaje = "";
        switch (args){
                case "-h":
                mensaje = "-----------------------------------------------------------------------------------------------------------------------------\n"
                        + "                             ALGORITMO CRIPTOGRAFICO DSA (DIGITAL SIGNATURE ALGORITHM)\n"
                        + "-----------------------------------------------------------------------------------------------------------------------------\n\n"
                        + "El algoritmo de firma digital (DSA, Digital Signature Algorithm) emplea un algoritmo de firma y cifrado distinto al del RSA, \n"
                        + "aunque ofrece el mismo nivel de seguridad. Lo propuso el National Institute of Standards and Technology (NIST) en 1991 y \n"
                        + "fue adoptado por los Federal Information Processing Standards (FIPS) en 1993. Desde entonces se ha revisado cuatro veces. \n"
                        + "\nEsta implementacion en Java de DSA cumple con las caracteristicas matematicas de números primos P,Q y utiliza un hash SHA-1\n"
                        + "sintaxis: java DSA <argumento>\n"
                        + "<argumento>:\n"
                        + "     -securitykey        Implementacion con java.security para crear el par llaves privada y publica.\n"
                        + "     -securitysign       Implementacion con java.security para firmar digitalmente un archivo.\n"
                        + "     -securityverify     Implementacion con java.security para verificar la autenticidad e integridad de un archivo.\n\n"
                        + "Para la ayuda de ejecucion cada parte del algoritmo, usar -h para cada argumento:\n\n"
                        + " Sintaxis: java DSA.java <argumento> -h\n\n\n"
                        + "Ejemplo: java DSA.java -securitykey -h\n\n"
                        + "Especializacion en Seguridad Informatica Universidad Autonoma de Occidente\n"    
                        + "Profesor: Siler Amador Donado\n"    
                        + "Elaborado por:  William Rojas Ordoñez   william_enr.rojas@uao.edu.co \n\n"    
                        ;    
                    break;
                
                case "-securitykey -h":
                    mensaje = "----------------------------------------------------------------------------------------------------------------------------\n"
                            + "                          GENERACION DE PAR LLAVES PRIVADA & PUBLICA PARA ALGORITMO DSA java.security\n"
                            + "-----------------------------------------------------------------------------------------------------------------------------\n"
                            + "Esta es la primera parte del algoritmo DSA, generar el par de llaves criptograficas publica y privada\n"
                            + "se generarán dos achivos .private y .public con la ejecución de esta parte del algoritmo. Las llaves son generadas por la libreria \n"
                            + "java.security y cumple con los requisitos del algoritmo DSA:\n"
                            + "Generar un numero primo p de longitud 1024 bits \n"
                            + "Generar un numero primo q de longitud 160 bits tal que p-1 mod q = 0 \n"
                            + "Un numero g tal que g^q mod p == 1 \n"
                            + "Un numero x (clave privada), número aleatorio que cumple con q > x \n"
                            + "Un numero y (clave publica), que cumple con g^x mod p == y \n\n"
                            + "Sintaxis: java DSA.java -securitykey <nombrellave>\n"
                            + "<nombrellave>:\n"
                            + "     <nombrellave>:     Nombre para los archivos de clave publica y privadas\n"
                            + "Ejemplo:     java DSA.java -securitykey keys\n";
                    break;
                
                case "-securitysign -h":
                    mensaje = "----------------------------------------------------------------------------------------------------------------------------------------------\n"
                            + "                                                 FIRMA ARCHIVO ALGORITMO DSA java.security\n"
                            + "----------------------------------------------------------------------------------------------------------------------------------------------\n"
                            + "Esta es la segunda parte del algoritmo DSA, firmar el archivo este algoritmo generara el archivo de firma .sign a partir\n"
                            + "de una llave privada. Los parametros para usar este algoritmo son la llave privada, el archivo a firmar y el nombre que se desea poner al archivo\n"
                            + "de firma.\n\n"
                            + "Sintaxis: java DSA.java -securitysign <LlavePrivada> <ArchivoAFirmar> <NombreFirma>\n"
                            + "<LlavePrivada>:      Archivo de Llave Privada.\n"
                            + "<ArchivoAFirmar>     Archivo para firmar digitalmente.\n"
                            + "<NombreFirma>        Nombre para el archivo de firma digital.\n\n"
                            + "Ejemplo:     java DSA.java -securitysign key.private Archivo.txt FirmaDigital\n";
                    break;    
                    
                case "-securityverify -h":
                    mensaje = "---------------------------------------------------------------------------------------------------------------------------------------------\n"
                            + "                                                 VERIFICAR FIRMA DIGITAL ALGORITMO DSA java.security\n"
                            + "---------------------------------------------------------------------------------------------------------------------------------------------\n"
                            + "Esta es la tercera parte del algoritmo DSA verificar la autenticidad de un archivo. Con la firma digital se certifica un documento\n"
                            + "y se le pone una marca de tiempo. Si el documento de manera posterior a la firma es editado, cualquier intento por verificar la firma fallaria.\n\n"
                            + "Sintaxis: java DSA.java -securityverify <LlavePublica> <ArchivoAVerificar> <FirmaDigital>\n"
                            + "<LlavePublica>:      Archivo de Llave Privada.\n"
                            + "<ArchivoAVerificar>  Archivo a verificar la autenticidad con la firma digital.\n"
                            + "<FirmaDigital>       Archivo de firma digital.\n\n"
                            + "Ejemplo:     java DSA.java -securityveryfy key.public Archivo.txt FirmaDigital.sig";
                    break;        
                default:
                    break;
                
        }         
        return mensaje;
    }
 }
