package org.brsm_system_server.controller;

import org.brsm_system_server.dto.UserDTO;
import org.brsm_system_server.entity.User;
import org.brsm_system_server.mapper.UserMapper;
import org.brsm_system_server.service.interfaces.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
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


}
