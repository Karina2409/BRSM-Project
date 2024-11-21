package org.brsm_system_server.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.util.Set;

@Data
@Entity
@Table(name = "students")
public class Student {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "student_id")
    private Long studentId;

    @ManyToMany
    @JoinTable(
            name = "students_has_events",
            joinColumns = @JoinColumn(name = "students_student_id"),
            inverseJoinColumns = @JoinColumn(name = "events_event_id")
    )
    private Set<Event> events;

}
