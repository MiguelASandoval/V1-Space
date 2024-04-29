import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;
import java.io.File;
import javax.crypto.SecretKey;


public class Admin {


    public static void accessEncryptedAdminReports(Scanner scnr) {
        System.out.println("Accessing Encrypted Admin Reports:");
        File encryptedFile = new File("EncryptedScholarshipSummaryReport.txt");
        File hashFile = new File("reportHash.txt");

        try {
            SecretKey secretKey = CryptoUtils.loadKeyFromFile(hashFile.getAbsolutePath());
            File decryptedFile = CryptoUtils.decryptToFile(encryptedFile, secretKey, "tempDecryptedReport.txt");
            CryptoUtils.FileOpener.openFile(decryptedFile);
            System.out.println("Report has been opened.");
        } catch (Exception e) {
            System.out.println("Failed to load key or decrypt file: " + e.getMessage());
            e.printStackTrace();
        }
    }
    

    public static String getDecryptedReportContent(File encryptedFile, SecretKey secretKey) {
        try {
            byte[] decryptedData = CryptoUtils.decryptFile(encryptedFile, secretKey);
            return new String(decryptedData);
        } catch (Exception e) {
            System.out.println("Error decrypting the report: " + e.getMessage());
            e.printStackTrace();
            return null; // or handle more gracefully depending on your error handling strategy
        }
    }


    public class ReportProcessor {
        public static void processAndDisplayReport(File encryptedFile, SecretKey secretKey) {
            String reportContent = Admin.getDecryptedReportContent(encryptedFile, secretKey);
            if (reportContent != null) {
                // Assume the report is structured as CSV
                String[] lines = reportContent.split("\n");
                for (String line : lines) {
                    String[] columns = line.split(",");
                    // Process columns as needed, for example:
                    System.out.println("Processed data: " + columns[0]); // Just an example
                }
            }
        }
    }

    public static void main(String[] args) {
        File encryptedFile = new File("EncryptedScholarshipSummaryReport.txt");
        File keyFile = new File("AESKey.key"); // Ensure the key is stored securely
        try {
            SecretKey secretKey = CryptoUtils.loadKeyFromFile("AESKey.key");
            if (CryptoUtils.verifyReportIntegrity(encryptedFile, new File("reportHash.txt"))) {
                ReportProcessor.processAndDisplayReport(encryptedFile, secretKey);
            } else {
                System.out.println("File integrity check failed. Cannot process the report.");
            }
        } catch (Exception e) {
            System.out.println("Failed to load key or process file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    
    public static void displayDecryptedReport(File encryptedFile, SecretKey secretKey) {
        try {
            byte[] decryptedData = CryptoUtils.decryptFile(encryptedFile, secretKey);
            String reportContent = new String(decryptedData);
            System.out.println("Decrypted Report Content:");
            System.out.println(reportContent);
        } catch (Exception e) {
            System.out.println("Error decrypting the report: " + e.getMessage());
            e.printStackTrace();
        }
    }



    public static void generateAdminReports(Scanner scnr) {
        
        
        System.out.println("============================");
        System.out.println("Admin Reports:");
        System.out.println("1. Scholarship Summary Report");
        System.out.println("2. Disbursement Report");
        System.out.println("3. Go back to main menu");

        int reportChoice = ReportEngineTest.getReportChoice(scnr);
        generateAdminReport(reportChoice, scnr);

          try {
            
            File reportFile = new File("ScholarshipSummaryReport.txt");
            SecretKey key = CryptoUtils.generateKey();  // Generate a new encryption key
            
            // Encrypt the file
            byte[] encryptedData = CryptoUtils.encryptFile(reportFile, key);
            File encryptedFile = new File("EncryptedScholarshipSummaryReport.txt");
            CryptoUtils.writeToFile(encryptedFile, encryptedData);
            
            // Compute and save the hash for later verification
            String hash = CryptoUtils.computeHash(encryptedData);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter("reportHash.txt"))) {
                writer.write(hash);
            }
            
            System.out.println("Report encrypted and hash saved.");
        } catch (Exception e) {
            System.out.println("Error encrypting report: " + e.getMessage());
            e.printStackTrace();
        }
    }
    

    private static void generateAdminReport(int choice, Scanner scnr) {
        try {
            switch (choice) {
                case 1:
                    generateScholarshipSummaryReport(scnr);
                    break;
                case 2:
                    generateDisbursementReport(scnr);
                    break;
                default:
                    System.out.println("Wrong report choice for Admin");
            }
        }  // or handle the exception as needed
        }
    

    public static void generateScholarshipSummaryReport(Scanner scnr) throws IOException {
        try (BufferedReader scholarshipData = new BufferedReader(new FileReader("ScholarshipData.txt"));
             BufferedReader scholarshipStatus = new BufferedReader(new FileReader("ScholarshipStatus.txt"));
             BufferedWriter scholarshipSummaryReport = new BufferedWriter(new FileWriter("ScholarshipSummaryReport.txt"))) {

            System.out.println("Enter the name of the scholarship for the summary report: ");
            scnr.nextLine();  // Consume the newline character
            String scholarshipName = scnr.nextLine();

            scholarshipSummaryReport.write("============================\n");
            scholarshipSummaryReport.write("Scholarship Summary Report for " + scholarshipName + ":\n");
            scholarshipSummaryReport.write("============================\n");

            int totalAmountAwarded = 0;

            String scholarshipDataLine;
            boolean scholarshipFound = false;

            while ((scholarshipDataLine = scholarshipData.readLine()) != null) {
                String[] data = scholarshipDataLine.split("\\|");
                String currentScholarshipName = data[0].trim();
                if (currentScholarshipName.equalsIgnoreCase(scholarshipName)) {
                    totalAmountAwarded = Integer.parseInt(data[1].trim());
                    scholarshipFound = true;
                    break;  // Found the scholarship, no need to continue searching
                }
            }

            if (!scholarshipFound) {
                throw new IllegalArgumentException("Scholarship not found. Please enter a valid name.");
            }

            scholarshipSummaryReport.write("Total Amount Awarded: $" + totalAmountAwarded + "\n");
            scholarshipSummaryReport.write("Names of Recipients: " + getAwardedStudents(scholarshipName, scholarshipStatus) + "\n\n");
            System.out.println("ScholarshipData.txt and ScholarshipStatus.txt read correctly.");
            System.out.println("Scholarship Summary Report for " + scholarshipName + " generated and saved to 'ScholarshipSummaryReport.txt'");

         // Re-throw the exception to be caught by the calling method
        }
    }

    private static String getAwardedStudents(String scholarshipName, BufferedReader scholarshipStatus) throws IOException {
        StringBuilder awardedStudents = new StringBuilder();

        String scholarshipStatusLine;
        while ((scholarshipStatusLine = scholarshipStatus.readLine()) != null) {
            String[] status = scholarshipStatusLine.split(",");
            String studentName = status[0].trim();

            for (int i = 1; i < status.length; i++) {
                String[] scholarshipInfo = status[i].split(":");
                if (scholarshipInfo.length == 2) {
                    String statusScholarshipName = scholarshipInfo[0].trim();
                    String awardStatus = scholarshipInfo[1].trim();

                    if (awardStatus.equalsIgnoreCase("Awarded") && statusScholarshipName.equalsIgnoreCase(scholarshipName)) {
                        awardedStudents.append(studentName).append(", ");
                    }
                }
            }
        }

        // Remove trailing comma and space
        
    }

    public static void generateDisbursementReport(Scanner scnr) throws IOException, ParseException {
        try (BufferedReader scholarshipData = new BufferedReader(new FileReader("ScholarshipData.txt"));
             BufferedReader scholarshipstatus = new BufferedReader(new FileReader("ScholarshipStatus.txt"));
             BufferedWriter DisbursementReportOutputFile = new BufferedWriter(new FileWriter("DisbursementReport.txt"))) {

            scnr.nextLine();
            System.out.println("Enter the name of the recipient: ");
            String recipientName = scnr.nextLine();

            System.out.println("Enter the name of the scholarship for the Disbursement report: ");
            String scholarshipName = scnr.nextLine();

            if (isRecipientAwarded(recipientName, scholarshipName, scholarshipstatus)) {
                DisbursementReportOutputFile.write("============================\n");
                DisbursementReportOutputFile.write("Disbursement Report for " + recipientName + " - " + scholarshipName + ":\n");
                DisbursementReportOutputFile.write("============================\n");

                String ScholarshipDataLine;
                boolean scholarshipFound = false;

                while ((ScholarshipDataLine = scholarshipData.readLine()) != null) {
                    String[] data = ScholarshipDataLine.split("\\|");
                    String currentScholarshipName = data[0].trim();
                    if (currentScholarshipName.equalsIgnoreCase(scholarshipName)) {
                        double disbursementAmount = Double.parseDouble(data[1].trim());
                        String date = data[5].trim();

                        SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yy");
                        Date disbursementdate = sdf.parse(date);

                        Calendar calendar = Calendar.getInstance();
                        calendar.setTime(disbursementdate);
                        calendar.add(Calendar.MONTH, 2);
                        Date newDisbursementDate = calendar.getTime();

                        DisbursementReportOutputFile.write("Recipient Name\t\t: " + recipientName + "\n");
                        DisbursementReportOutputFile.write("Scholarship Name\t: " + scholarshipName + "\n");
                        DisbursementReportOutputFile.write("Disbursement Amount\t: $" + disbursementAmount + "\n");
                        DisbursementReportOutputFile.write("Disbursement Date\t: " + sdf.format(newDisbursementDate) + "\n");

                        System.out.println("============================");
                        System.out.println("ScholarshipData.txt and ScholarshipStatus.txt read correctly.");
                        System.out.println("Disbursement Report written for " + recipientName + " and written to DisbursementReport.txt");
                        System.out.println("============================");
                        scholarshipFound = true;
                        break;
                    }
                }

                if (!scholarshipFound) {
                    throw new IllegalArgumentException("Scholarship not found. Please enter a valid name.");
                }
            } else {
                System.out.println("Recipient not awarded the specified scholarship. Unable to generate the disbursement report.");
            }

        } catch (IOException | ParseException e) {
            throw e; // Re-throw the exception to be caught by the calling method
        }
    }

    private static boolean isRecipientAwarded(String recipientName, String scholarshipName, BufferedReader scholarshipStatus) throws IOException {
        String scholarshipStatusLine;
        while ((scholarshipStatusLine = scholarshipStatus.readLine()) != null) {
            String[] status = scholarshipStatusLine.split(",");
            String studentName = status[0].trim();

            if (studentName.equalsIgnoreCase(recipientName)) {
                for (int i = 1; i < status.length; i++) {
                    String[] scholarshipInfo = status[i].split(":");
                    if (scholarshipInfo.length == 2) {
                        String statusScholarshipName = scholarshipInfo[0].trim();
                        String awardStatus = scholarshipInfo[1].trim();

                        if (awardStatus.equalsIgnoreCase("Awarded") && statusScholarshipName.equalsIgnoreCase(scholarshipName)) {
                            return true;
                        }
                    }
                }
                // If the recipient is found but not awarded the specified scholarship
                return false;
            }
        }

        // Recipient not found
        return false;
        
    }
    
}
