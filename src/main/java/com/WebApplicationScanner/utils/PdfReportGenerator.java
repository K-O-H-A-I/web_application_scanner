package main.java.com.WebApplicationScanner.utils;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Element;
import com.itextpdf.text.Font;
import com.itextpdf.text.FontFactory;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfWriter;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class PdfReportGenerator {

    /**
     * Generates a structured PDF report with the provided scan content and saves it to the given file path.
     *
     * @param scanContent The detailed scan report content.
     * @param filePath    The full file path where the PDF report should be saved.
     */
    public void generateReport(String scanContent, String filePath) {
        Document document = new Document();
        try {
            PdfWriter.getInstance(document, new FileOutputStream(filePath));
            document.open();

            // Add Title
            Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 20);
            Paragraph title = new Paragraph("Web Application Security Scan Report", titleFont);
            title.setAlignment(Element.ALIGN_CENTER);
            document.add(title);

            // Add Subtitle with timestamp
            Font subTitleFont = FontFactory.getFont(FontFactory.HELVETICA, 12);
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            Paragraph subTitle = new Paragraph("Generated on: " + timestamp, subTitleFont);
            subTitle.setAlignment(Element.ALIGN_CENTER);
            document.add(subTitle);

            // Spacer
            document.add(new Paragraph("\n"));

            // Add Introduction Section
            Font sectionHeaderFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14);
            Paragraph introHeader = new Paragraph("Introduction", sectionHeaderFont);
            document.add(introHeader);
            Font contentFont = FontFactory.getFont(FontFactory.HELVETICA, 12);
            Paragraph introduction = new Paragraph("This report details the results of a comprehensive vulnerability scan performed on the target web application. The scan covers multiple vulnerabilities including SQL Injection, Cross-Site Scripting (XSS), and Cross-Site Request Forgery (CSRF).", contentFont);
            document.add(introduction);

            // Spacer
            document.add(new Paragraph("\n"));

            // Add Findings Section
            Paragraph findingsHeader = new Paragraph("Findings", sectionHeaderFont);
            document.add(findingsHeader);
            Paragraph findingsContent = new Paragraph(scanContent, contentFont);
            document.add(findingsContent);

            // Spacer
            document.add(new Paragraph("\n"));

            // Add Recommendations Section (placeholder for future details)
            Paragraph recommendationsHeader = new Paragraph("Recommendations", sectionHeaderFont);
            document.add(recommendationsHeader);
            Paragraph recommendationsContent = new Paragraph("Based on the scan findings, it is recommended to review input validation and sanitization processes, apply parameterized queries to mitigate SQL injection, and implement proper CSRF tokens. Further investigation is advised for any vulnerabilities detected.", contentFont);
            document.add(recommendationsContent);

            // Spacer
            document.add(new Paragraph("\n"));

            // Add Footer
            Paragraph footer = new Paragraph("End of Report", contentFont);
            footer.setAlignment(Element.ALIGN_CENTER);
            document.add(footer);

        } catch (DocumentException | FileNotFoundException e) {
            e.printStackTrace();
        } finally {
            document.close();
        }
    }
}
