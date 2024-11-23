package org.brsm_system_server.dto;

import lombok.Data;
import org.brsm_system_server.entity.Event;
import org.brsm_system_server.entity.enums.FacultyEnum;

import java.util.Set;

@Data
public class StudentDTO {
    private Long studentId;
    private String studentFullNameD;
    private String lastName;
    private String firstName;
    private String middleName;
    private String groupNumber;
    private FacultyEnum studentFaculty;
    private boolean dormitoryResidence;
    private String dormBlockNumber;
    private Integer dormNumber;
}
