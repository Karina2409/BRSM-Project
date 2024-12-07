package org.brsm_system_server.repository;

import jakarta.transaction.Transactional;
import org.brsm_system_server.entity.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface StudentEventRepository extends JpaRepository<Student, Long> {

    @Modifying
    @Transactional
    @Query(value = "DELETE FROM students_has_events WHERE events_event_id = :eventId", nativeQuery = true)
    void deleteByEventId(@Param("eventId") Long eventId);

}
