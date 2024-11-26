package org.brsm_system_server.repository;

import org.brsm_system_server.entity.Event;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface EventRepository extends JpaRepository<Event, Long> {

    @Query("SELECT e FROM Event e JOIN e.students s WHERE s.studentId = :studentId")
    List<Event> findEventsByStudentId(@Param("studentId") Long studentId);

}
