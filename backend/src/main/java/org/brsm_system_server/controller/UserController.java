package org.brsm_system_server.controller;

import org.brsm_system_server.dto.UserDTO;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.entity.User;
import org.brsm_system_server.mapper.UserMapper;
import org.brsm_system_server.service.interfaces.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private IUserService userService;

    @PreAuthorize("hasAnyAuthority('CHIEF_SECRETARY')")
    @GetMapping
    public List<UserDTO> getUsers() {
        List<User> users = userService.findAllUsers();
        return users.stream().map(user -> {
            return UserMapper.toDTO(user, userService);
        }).toList();
    }

    @PreAuthorize("hasAuthority('STUDENT')")
    @GetMapping("/student/{userId}")
    public ResponseEntity<Student> getStudent(@PathVariable Long userId) {

        Student student = userService.findStudentById(userId);
        if (student != null) {
            return ResponseEntity.ok(student);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

}
