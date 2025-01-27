package main.java.com.WebApplicationScanner.utils;

import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfWriter;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class PdfReportGenerator {

    public void generateReport(String scanResults, String filePath) {
        Document document = new Document();
        try {
            PdfWriter.getInstance(document, new FileOutputStream(filePath));
            document.open();

            // Title
            Font titleFont = new Font(Font.FontFamily.HELVETICA, 18, Font.BOLD);
            Paragraph title = new Paragraph("Web Application Security Scan Report", titleFont);
            title.setAlignment(Element.ALIGN_CENTER);
            document.add(title);

            // Spacer
            document.add(new Paragraph("\n"));

            // Scan Results
            Font contentFont = new Font(Font.FontFamily.HELVETICA, 12, Font.NORMAL);
            Paragraph content = new Paragraph(scanResults, contentFont);
            content.setAlignment(Element.ALIGN_LEFT);
            document.add(content);

            // Footer
            document.add(new Paragraph("\n"));
            Paragraph footer = new Paragraph("Generated on: " + java.time.LocalDate.now(), contentFont);
            footer.setAlignment(Element.ALIGN_RIGHT);
            document.add(footer);

        } catch (DocumentException | FileNotFoundException e) {
            e.printStackTrace();
        } finally {
            document.close();
        }
    }
}
