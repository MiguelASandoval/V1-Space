import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;

public class Reviewer {
    private static boolean menu = true;

    public static void generateReviewerReports(Scanner scnr) {
        while (menu) {
            System.out.println("===================================");
            System.out.println("Reviewer Reports:");
            System.out.println("1. Applicant Report");
            System.out.println("2. Reviewable Applications Report");
            System.out.println("3. Scholarship Summary Report");
            System.out.println("4. Go back to main menu ");

            int reportChoice = ReportEngineTest.getReportChoice(scnr);
            if (reportChoice == 4) {
                menu = true;
                return;
            }

            try {
                generateReviewerReport(reportChoice, scnr);
            } catch (IllegalArgumentException e) {
                System.out.println(e.getMessage());
            }
        }
    }

    private static void generateReviewerReport(int choice, Scanner scnr) {
        try {
            switch (choice) {
                case 1:
                    generateReviewerApplicantReport(scnr);
                    break;
                case 2:
                    generateReviewableApplicationsReport(scnr);
                    break;
                case 3:
                    generateScholarshipSummaryReport(scnr);
                    break;
                default:
                    throw new IllegalArgumentException("Wrong report choice for reviewers");
            }
        } catch (IOException e) {
            e.printStackTrace(); // or handle the exception as needed
        }
    }
    


    public static void generateReviewerApplicantReport(Scanner scnr) {
        try (BufferedReader personalInfo = new BufferedReader(new FileReader("personal_info.txt"));
             BufferedReader awardedScholarshipsInfo = new BufferedReader(new FileReader("awarded_scholarships.txt"));
             BufferedWriter applicantReportoutputFile = new BufferedWriter(new FileWriter("reviewer_applicant_report.txt"))) {

            System.out.println("Enter name of student: ");
            scnr.nextLine();
            String studentName = scnr.nextLine();

            boolean studentFound = false;

            String studentPersonalInfoLine;
            while ((studentPersonalInfoLine = personalInfo.readLine()) != null) {
                String[] student = studentPersonalInfoLine.split(",");
                if (student[0].equalsIgnoreCase(studentName.trim())) {
                    applicantReportoutputFile.write("===================================\n");
                    applicantReportoutputFile.write("Applicant Report for " + student[0] + ":\n");
                    applicantReportoutputFile.write("===================================\n");
                    applicantReportoutputFile.write("Name: " + student[0] + "\n");
                    applicantReportoutputFile.write("GPA: " + student[1] + "\n");
                    applicantReportoutputFile.write("Intended Graduation Year: " + student[2] + "\n");
                    applicantReportoutputFile.write("Major: " + student[3] + "\n\n");
                    studentFound = true;
                    break;
                }
            }

          
            applicantReportoutputFile.write("===================================\n");
            applicantReportoutputFile.write("Previously awarded scholarships:\n");
            String awardedScholarshipsLine;

            while ((awardedScholarshipsLine = awardedScholarshipsInfo.readLine()) != null) {
                String[] scholarships = awardedScholarshipsLine.split(",");
                if (scholarships[0].equalsIgnoreCase(studentName.trim())) {
                    for (int i = 1; i < scholarships.length; i++) {
                        applicantReportoutputFile.write("- " + scholarships[i] + "\n");
                    }
                    break;
                }
            }
            System.out.println("===================================");
            System.out.println("personal_info.txt and awarded_scholarships.txt read correctly");
            System.out.println("Applicant report generated and saved to 'reviewer_applicant_report.txt'");

        } 
        }
    }

    public static void generateReviewableApplicationsReport(Scanner scnr) {
        try (BufferedReader reviewerScholarships = new BufferedReader(new FileReader("ReviewerScholarships.txt"));
             BufferedWriter scholarshipsToReviewOutputFile = new BufferedWriter(new FileWriter("ScholarshipsToReview.txt"))) {

            System.out.println("Enter applicant name to see reviewable scholarships: ");
            scnr.nextLine();
            String studentName = scnr.nextLine();

            boolean studentFound = false;

            String line;
            while ((line = reviewerScholarships.readLine()) != null) {
                String[] review = line.split(",");
                if (review.length >= 2 && review[0].equalsIgnoreCase(studentName.trim())) {
                    scholarshipsToReviewOutputFile.write("Scholarships to be reviewed for " + studentName + ":" + "\n");

                    for (int i = 1; i < review.length; i++) {
                        String[] scholarshipInfo = review[i].split(":");
                        if (scholarshipInfo.length == 2) {
                            String scholarshipName = scholarshipInfo[0].trim();
                            String status = scholarshipInfo[1].trim();

                            if (status.equalsIgnoreCase("Submitted")) {
                                scholarshipsToReviewOutputFile.write("- " + scholarshipName + "\n");
                            }
                        }
                    }
                    studentFound = true;
                    break;
                }
            }

            
            System.out.println("===================================");
            System.out.println("ReviewerScholarships.txt read correctly.");
            System.out.println("Scholarships for " + studentName + " written to ScholarshipsToReview.txt");

        
        }
    }

    public static void generateScholarshipSummaryReport(Scanner scnr) throws IOException {
        try (BufferedReader scholarshipData = new BufferedReader(new FileReader("ScholarshipData.txt"));
             BufferedReader scholarshipStatus = new BufferedReader(new FileReader("ScholarshipStatus.txt"));
             BufferedWriter scholarshipSummaryReport = new BufferedWriter(new FileWriter("ScholarshipSummaryReport.txt"))) {

            System.out.println("Enter the name of the scholarship for the summary report: ");
            scnr.nextLine();  // Consume the newline character
            String scholarshipName = scnr.nextLine();

            boolean scholarshipFound = false;

            // Validate scholarship name
            String dataLine;
            while ((dataLine = scholarshipData.readLine()) != null) {
                String[] data = dataLine.split("\\|");
                if (data.length > 0 && data[0].trim().equalsIgnoreCase(scholarshipName)) {
                    scholarshipFound = true;
                    break;
                }
            }

           
            scholarshipSummaryReport.write("===================================\n");
            scholarshipSummaryReport.write("Scholarship Summary Report for " + scholarshipName + ":\n");
            scholarshipSummaryReport.write("============================\n");

            int totalAmountAwarded = 0;

            String scholarshipDataLine;
            while ((scholarshipDataLine = scholarshipData.readLine()) != null) {
                String[] data = scholarshipDataLine.split("\\|");
                String currentScholarshipName = data[0].trim();
                if (currentScholarshipName.equalsIgnoreCase(scholarshipName)) {
                    totalAmountAwarded = Integer.parseInt(data[1].trim());
                    break;  // Found the scholarship, no need to continue searching
                }
            }

            scholarshipSummaryReport.write("Total Amount Awarded: $" + totalAmountAwarded + "\n");
            scholarshipSummaryReport.write("Names of Recipients: " + getAwardedStudents(scholarshipName, scholarshipStatus) + "\n\n");
            
            System.out.println("===================================");
            System.out.println("ScholarshipData.txt and ScholarshipStatus.txt read correctly.");
            System.out.println("Scholarship Summary Report for " + scholarshipName + " generated and saved to 'ScholarshipSummaryReport.txt'");

        } 
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
        if (awardedStudents.length() > 0) {
            awardedStudents.setLength(awardedStudents.length() - 2);
        }

        return awardedStudents.toString();
    }
}
