package org.brsm_system_server.service.interfaces;

import org.brsm_system_server.entity.Student;

import java.util.List;

public interface IStudentService {

    List<Student> findAllStudents();

}
