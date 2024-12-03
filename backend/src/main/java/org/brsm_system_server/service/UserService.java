package org.brsm_system_server.service;

import org.brsm_system_server.entity.Secretary;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.entity.User;
import org.brsm_system_server.repository.UserRepository;
import org.brsm_system_server.service.interfaces.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService implements IUserService {

    @Autowired
    UserRepository userRepository;

    @Override
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public Student findStudentById(Long id) {
        User userP = userRepository.findById(id).orElse(null);
        if (userP != null) {
            Student student = userP.getStudent();
            return student;
        }
        return null;
    }

    @Override
    public Secretary findSecretaryById(Long id) {
        User userP = userRepository.findById(id).orElse(null);
        if (userP != null) {
            Secretary secretary = userP.getSecretary();
            return secretary;
        }
        return null;
    }
}
