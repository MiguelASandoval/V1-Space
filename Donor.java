import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;
import java.io.File;
import javax.crypto.SecretKey;

public class Donor {
    private static boolean menu = true;

    public static void generateDonorReports(Scanner scnr) {
        while (menu) {
            System.out.println("===================================");
            System.out.println("Donor Report:");
            System.out.println("1. Donor Summary Report");
            System.out.println("4. Go back to main menu ");

            int reportChoice = ReportEngineTest.getReportChoice(scnr);
            if (reportChoice == 4) {
                menu = true;
                return;
            } else if (reportChoice == 1) {
                System.out.println("Would you like to preview this report?: ");
                System.out.println("Enter (Y/N): ");
                String previewChoice = scnr.next();

                if (previewChoice.equalsIgnoreCase("Y")) {
                    generateDonorPreview(scnr);
                }
                generateDonorReport(reportChoice, scnr);
            }
        }
        try {
            // Assume outputFile is the file you want to encrypt and save
            File reportFile = new File("donor_Report.txt");
            SecretKey key = CryptoUtils.generateKey();  // Generate a new encryption key
            
            // Encrypt the file
            byte[] encryptedData = CryptoUtils.encryptFile(reportFile, key);
            File encryptedFile = new File("Encrypteddonor_Report.txt");
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

    private static void generateDonorReport(int choice, Scanner scnr) {
        try {
            switch (choice) {
                case 1:
                    generateDonorSummaryReport(scnr);
                    break;
                default:
                    System.out.println("Wrong report choice for donors");
            }
        } catch (IOException e) {
            e.printStackTrace(); // or handle the exception as needed
        }
    }

    private static void generateDonorPreview(Scanner scnr) {
        System.out.println("Preview Generated: ");
        System.out.println("===================================");
        System.out.println("Donor Report: \n");
        System.out.println("===================================\n");
        System.out.println("Scholarship: 'Example Scholarship'\n");
        System.out.println("Status: 'Closed'\n");
        System.out.println("Award Amount: '1000' \n");
        System.out.println("Number of applicants awarded: '10'\n");
        System.out.println("Total amount awarded: '10,000' \n");
        System.out.println("Date closed on:  '01/01/23' \n");
        System.out.println("===================================\n");
    }

    private static void generateDonorSummaryReport(Scanner scnr) throws IOException {
        try (BufferedReader scholarshipsList = new BufferedReader(new FileReader("DonorScholarshipStatus.txt"));
             BufferedWriter donorReportOutputFile = new BufferedWriter(new FileWriter("donor_Report.txt"))) {

            System.out.println("Enter the name of your scholarship: ");
            scnr.nextLine();
            String scholarshipName = scnr.nextLine();

            String scholarshipLine;// read file
            boolean scholarshipFound = false;

            while ((scholarshipLine = scholarshipsList.readLine()) != null) {
                String[] scholarship = scholarshipLine.split(",");
                

                if (scholarship[0].equalsIgnoreCase(scholarshipName.trim()) && scholarship[3].equals("Closed")) {
                    donorReportOutputFile.write("===================================\n");
                    donorReportOutputFile.write("Donor Report: \n");
                    donorReportOutputFile.write("===================================\n");
                    donorReportOutputFile.write("Scholarship: " + scholarship[0] + ":\n");
                    donorReportOutputFile.write("Status: " + scholarship[3] + "\n");
                    donorReportOutputFile.write("Award Amount: " + scholarship[1] + "\n");
                    donorReportOutputFile.write("Number of applicants awarded: " + scholarship[2] + "\n");
                    donorReportOutputFile.write("Date closed on:  " + scholarship[4] + "\n");
                    donorReportOutputFile.write("===================================\n");
                    scholarshipFound = true;
                    break;
                } else if (scholarship[0].equalsIgnoreCase(scholarshipName.trim())) {
                    donorReportOutputFile.write("===================================\n");
                    donorReportOutputFile.write("Donor Report: \n");
                    donorReportOutputFile.write("===================================\n");
                    donorReportOutputFile.write("Scholarship: " + scholarship[0] + ":\n");
                    donorReportOutputFile.write("Status: " + scholarship[3] + "\n");
                    donorReportOutputFile.write("Award Amount: " + scholarship[1] + "\n");
                    donorReportOutputFile.write("Number of applicants to be awarded: " + scholarship[2] + "\n");
                    donorReportOutputFile.write("Date to be closed on:  " + scholarship[4] + "\n");
                    donorReportOutputFile.write("===================================\n");
                    scholarshipFound = true;
                    break;
                }
            }

            if (!scholarshipFound) {
                throw new IllegalArgumentException("Scholarship not found. Please enter a valid name.");
            }
            System.out.println("===================================");
            System.out.println("DonorScholarshipStatus.txt read correctly.");
            System.out.println("Donor Summary Report generated and saved to 'donor_Report.txt'");
            
        }
    }
}
