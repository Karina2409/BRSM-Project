package org.brsm_system_server.repository;

import org.brsm_system_server.entity.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface StudentRepository extends JpaRepository<Student, Long> {
    @Query("SELECT s FROM Student s JOIN s.events e WHERE e.eventId = :eventId")
    List<Student> findStudentsByEventId(@Param("eventId") Long eventId);
}
