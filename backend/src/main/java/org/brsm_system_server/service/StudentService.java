package org.brsm_system_server.service;

import org.brsm_system_server.entity.Student;
import org.brsm_system_server.repository.StudentRepository;
import org.brsm_system_server.service.interfaces.IStudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class StudentService implements IStudentService {

    @Autowired
    private StudentRepository studentRepository;

    @Override
    public List<Student> findAllStudents(){
        return studentRepository.findAll();
    }

    @Override
    public Student getStudentById(Long id){
        Optional<Student> optionalStudent = studentRepository.findById(id);
        return optionalStudent.orElse(null);
    }

    @Override
    public List<Student> getStudentsByEventId(Long eventId) {
        return studentRepository.findStudentsByEventId(eventId);
    }

}
