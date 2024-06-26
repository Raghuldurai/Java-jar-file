import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Raghul extends JFrame {
    private JButton selectFileButton;
    private JButton encryptButton;
    private JButton decryptButton;
    private JTextArea outputArea;
    private File selectedFile;
    private static final String SECRET_KEY = "1234567890123456"; 
    private static final String USER_ID = "rahul";
    private static final String PASSWORD = "java123";

    public Raghul() {
        // Initial login dialog
        login();

        setTitle("File Encrypt/Decrypt");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(3, 1));

        selectFileButton = new JButton("Select File");
        panel.add(selectFileButton);

        encryptButton = new JButton("Encrypt");
        panel.add(encryptButton);

        decryptButton = new JButton("Decrypt");
        panel.add(decryptButton);

        add(panel, BorderLayout.NORTH);

        outputArea = new JTextArea();
        add(new JScrollPane(outputArea), BorderLayout.CENTER);

        // Action listeners
        selectFileButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int option = fileChooser.showOpenDialog(Raghul.this);
                if (option == JFileChooser.APPROVE_OPTION) {
                    selectedFile = fileChooser.getSelectedFile();
                    outputArea.setText("Selected file: " + selectedFile.getAbsolutePath());
                }
            }
        });

        encryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (selectedFile == null) {
                    outputArea.setText("Please select a file first.");
                    return;
                }
                try {
                    String newFileName = getNewFileName(selectedFile, "enc");
                    encryptFile(selectedFile.getAbsolutePath(), SECRET_KEY, newFileName);
                    outputArea.append("\nFile encrypted successfully! Saved as: " + newFileName);
                } catch (Exception ex) {
                    outputArea.append("\nError: " + ex.getMessage());
                }
            }
        });

        decryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (selectedFile == null) {
                    outputArea.setText("Please select a file first.");
                    return;
                }
                try {
                    String newFileName = getNewFileName(selectedFile, "dec");
                    decryptFile(selectedFile.getAbsolutePath(), SECRET_KEY, newFileName);
                    outputArea.append("\nFile decrypted successfully! Saved as: " + newFileName);
                } catch (Exception ex) {
                    outputArea.append("\nError: " + ex.getMessage());
                }
            }
        });
    }

    private void login() {
        JTextField idField = new JTextField();
        JPasswordField passwordField = new JPasswordField();
        Object[] message = {
            "ID:", idField,
            "Password:", passwordField
        };

        int option = JOptionPane.showConfirmDialog(null, message, "Login", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            String enteredId = idField.getText();
            String enteredPassword = new String(passwordField.getPassword());

            if (USER_ID.equals(enteredId) && PASSWORD.equals(enteredPassword)) {
                // Login successful
                return;
            } else {
                // Login failed
                JOptionPane.showMessageDialog(null, "ID or Password is incorrect", "Error", JOptionPane.ERROR_MESSAGE);
                login();
            }
        } else {
            System.exit(0);
        }
    }

    private String getNewFileName(File file, String suffix) {
        String filePath = file.getAbsolutePath();
        int dotIndex = filePath.lastIndexOf('.');
        if (dotIndex != -1) {
            filePath = filePath.substring(0, dotIndex);
        }
        return filePath + "." + suffix;
    }

    private void encryptFile(String filePath, String key, String newFileName) throws Exception {
        byte[] fileData = Files.readAllBytes(Paths.get(filePath));
        byte[] encryptedData = encrypt(fileData, key);
        Files.write(Paths.get(newFileName), encryptedData);
    }

    private void decryptFile(String filePath, String key, String newFileName) throws Exception {
        byte[] fileData = Files.readAllBytes(Paths.get(filePath));
        byte[] decryptedData = decrypt(fileData, key);
        Files.write(Paths.get(newFileName), decryptedData);
    }

    private byte[] encrypt(byte[] data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    private byte[] decrypt(byte[] data, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new Raghul().setVisible(true);
            }
        });
    }
}
