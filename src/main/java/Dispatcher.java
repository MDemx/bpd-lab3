import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Dispatcher {
    private static final Rc5CbcPadUtils.WordLength WORD_LENGTH = Rc5CbcPadUtils.WordLength._16;
    private static final int NUMBER_OF_ROUNDS = 12;
    private static final int SECRET_KEY_LENGTH = 16;
    private static final Logger LOGGER = Logger.getLogger(Dispatcher.class.getName());
    private final Scanner scanner = new Scanner(System.in);
    private Rc5CbcPadUtils rc5CbcPadUtils;

    public void start() {
        updateRc5Password();

        System.out.println("""
                Options:
                  1 - encrypt file
                  2 - decrypt file
                  3 - encrypt message
                  4 - decrypt message
                  5 - change password
                  0 - exit
                """);

        while (true) {
            System.out.print("<---->\nInput option: ");
            try {
                switch (scanner.next()) {
                    case "1" -> encryptFile();
                    case "2" -> decryptFile();
                    case "3" -> encryptMessage();
                    case "4" -> decryptMessage();
                    case "5" -> updateRc5Password();
                    case "0" -> {
                        return;
                    }
                }
            } catch (Exception e) {
                System.out.println("Unexpected error");
                LOGGER.log(Level.ALL, e.getMessage());
            }
        }
    }

    private void encryptFile() {
        try {
            System.out.print("File to encrypt: ");
            String sourceFilePath = scanner.next();
            System.out.print("Encrypted file destination: ");
            String destinationFilePath = scanner.next();

            Path sourcePath = Paths.get(sourceFilePath);
            Path destinationPath = Paths.get(destinationFilePath);

            byte[] sourceBytes = Files.readAllBytes(sourcePath);
            byte[] destinationBytes = rc5CbcPadUtils.encryptCbc(sourceBytes);

            Files.write(destinationPath, destinationBytes);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void decryptFile() {
        try {
            System.out.print("File to decrypt: ");
            String sourceFilePath = scanner.next();
            System.out.print("Decrypted file destination: ");
            String destinationFilePath = scanner.next();

            Path sourcePath = Paths.get(sourceFilePath);
            Path destinationPath = Paths.get(destinationFilePath);

            byte[] sourceBytes = Files.readAllBytes(sourcePath);
            byte[] destinationBytes = rc5CbcPadUtils.decryptCbc(sourceBytes);

            Files.write(destinationPath, destinationBytes);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void updateRc5Password() {
        System.out.print("Input RC5 password: ");
        this.rc5CbcPadUtils = new Rc5CbcPadUtils(WORD_LENGTH, NUMBER_OF_ROUNDS, SECRET_KEY_LENGTH, scanner.next());
    }

    private void encryptMessage() {
        System.out.print("Message to encrypt: ");
        String sourceMessage = scanner.next();

        byte[] resultBytes = rc5CbcPadUtils.encryptCbc(sourceMessage.getBytes());

        System.out.println("Encrypted message:");
        System.out.println(new String(Base64.getEncoder().encode(resultBytes)));
    }

    private void decryptMessage() {
        System.out.print("64Based message to decrypt: ");
        String sourceMessage = scanner.next();

        byte[] resultBytes = rc5CbcPadUtils.decryptCbc(Base64.getDecoder().decode(sourceMessage.getBytes()));

        System.out.println("Decrypted message:");
        System.out.println(new String(resultBytes));
    }

    public static void main(String[] args) {
        new Dispatcher().start();
    }
}
