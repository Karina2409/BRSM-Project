package org.brsm_system_server.service.interfaces;

import org.brsm_system_server.entity.Secretary;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.entity.User;

import java.util.List;

public interface IUserService {
    List<User> findAllUsers();
    Student findStudentById(Long id);
    Secretary findSecretaryById(Long id);
}
