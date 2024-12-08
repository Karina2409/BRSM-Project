package org.brsm_system_server.service;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;
import org.brsm_system_server.entity.DeanData;
import org.brsm_system_server.entity.Exemption;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.entity.enums.FacultyEnum;
import org.brsm_system_server.help.DateFormat;
import org.brsm_system_server.pdf.ExemptionTemplate;
import org.brsm_system_server.pdf.PdfGenerator;
import org.brsm_system_server.repository.EventRepository;
import org.brsm_system_server.repository.ExemptionRepository;
import org.brsm_system_server.repository.ExemptionStudentsRepository;
import org.brsm_system_server.service.interfaces.IExemptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class ExemptionService implements IExemptionService {

    @Autowired
    private ExemptionRepository exemptionRepository;

    @Autowired
    private ExemptionStudentsRepository exemptionStudentsRepository;

    @Autowired
    private EventRepository eventRepository;

    @Override
    public List<Exemption> getAllExemptions() {
        return exemptionRepository.findAll();
    }

    @Override
    public ResponseEntity<Void> deleteExemptionById(Long exemptionId) {
        Optional<Exemption> exemption = exemptionRepository.findById(exemptionId);
        exemptionStudentsRepository.delete(exemptionStudentsRepository.findById(exemptionId).get());
        if (exemption.isPresent()) {
            exemptionRepository.delete(exemption.get());
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @Override
    public ResponseEntity<Void> downloadExemption(Long exemptionId) {
        PdfGenerator pdfGenerator = new PdfGenerator();

        ExemptionTemplate exemptionTemplate = new ExemptionTemplate(eventRepository);
        String directoryName = "D:/BRSM project/документация/освобождения";

        Path directoryPath = Paths.get(directoryName);

        Set<Student> students = exemptionStudentsRepository.findStudentsByExemptionId(exemptionId);

        Exemption exemption = exemptionRepository.findById(exemptionId).get();

        FacultyEnum faculty = exemption.getStudentsFacultyExemption();



        StringBuilder studentsInfo = new StringBuilder();
        int k = 0;
        String exemptionHeader = exemptionTemplate.generateHeader(faculty,
                DeanData.getFacultyDean(faculty));
        for (Student student : students) {
            if (k != 0) {
                studentsInfo.append(", ");
            }
            studentsInfo.append("гр. ")
                    .append(student.getGroupNumber())
                    .append(" ")
                    .append(student.getLastName())
                    .append(" ")
                    .append(student.getFirstName())
                    .append(" ")
                    .append(student.getMiddleName());
            k++;

        }
        String exemptionContent = exemptionTemplate.generateContent(
                studentsInfo,
                exemption.getEvent().getEventId()
        );

        try {
            if (!Files.exists(directoryPath)) {
                Files.createDirectories(directoryPath);
            }
            String fileName = directoryName + "/освобождение_" + DateFormat.Date_Format(exemption.getExemptionDate()) + "_" + faculty + ".pdf";
            float[] columnWidths = {3, 1};
            pdfGenerator.createPDF(fileName, exemptionHeader, exemptionTemplate.generateBeforeContent(), exemptionContent, columnWidths);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PdfWriter writer = new PdfWriter(outputStream);
            PdfDocument pdfDocument = new PdfDocument(writer);

            Document document = new Document(pdfDocument);
            document.add(new Paragraph(exemptionContent));
            document.close();
            return ResponseEntity.ok().build();

        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.notFound().build();
        }
    }
}
