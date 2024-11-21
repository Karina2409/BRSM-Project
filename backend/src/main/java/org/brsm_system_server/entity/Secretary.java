package org.brsm_system_server.entity;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "secretaries")
public class Secretary {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "secretary_id")
    private Long secretaryId;

}
