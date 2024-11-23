package org.brsm_system_server.service;

import org.brsm_system_server.entity.Student;
import org.brsm_system_server.repository.StudentRepository;
import org.brsm_system_server.service.interfaces.IStudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class StudentService implements IStudentService {

    @Autowired
    private StudentRepository studentRepository;

    @Override
    public List<Student> findAllStudents(){
        return studentRepository.findAll();
    }

}
