package org.brsm_system_server.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.brsm_system_server.dto.StudentDTO;
import org.brsm_system_server.entity.Event;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.service.interfaces.IEventService;
import org.brsm_system_server.service.interfaces.IStudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/students")
@Slf4j
@CrossOrigin(origins = "http://127.0.0.1:8081", allowedHeaders = {"*", "Content-Type, Authorization"}, methods = {RequestMethod.DELETE, RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT}, allowCredentials = "true")
@RequiredArgsConstructor
public class StudentController {

    @Autowired
    private IStudentService studentService;

    @Autowired
    private IEventService eventService;

    @PreAuthorize("hasAuthority('SECRETARY')")
    @GetMapping("/get-all")
    public List<StudentDTO> getStudents() {
        List<Student> students = studentService.findAllStudents();
        log.info("Called allStudents endpoint");

        return students.stream().map(student -> {
            StudentDTO dto = new StudentDTO();
            dto.setStudentId(student.getStudentId());
            dto.setStudentFullNameD(student.getStudentFullNameD());
            dto.setLastName(student.getLastName());
            dto.setFirstName(student.getFirstName());
            dto.setMiddleName(student.getMiddleName());
            dto.setGroupNumber(student.getGroupNumber());
            dto.setStudentFaculty(student.getStudentFaculty());
            dto.setDormitoryResidence(student.isDormitoryResidence());
            dto.setDormBlockNumber(student.getDormBlockNumber());
            dto.setDormNumber(student.getDormNumber());
            return dto;
        }).toList();
    }

    @GetMapping("/{studentId}")
    public Student getStudentById(@PathVariable Long studentId){
        return studentService.getStudentById(studentId);
    }


    @GetMapping("/{studentId}/events")
    public List<Event> getEventsByStudentId(@PathVariable Long studentId) {
        return eventService.getEventsByStudentId(studentId);
    }

}
