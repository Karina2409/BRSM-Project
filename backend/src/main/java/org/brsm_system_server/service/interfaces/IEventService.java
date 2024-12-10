package org.brsm_system_server.service.interfaces;

import org.brsm_system_server.entity.Event;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface IEventService {
    List<Event> findAllEvents();
    List<Event> getEventsByStudentId(Long studentId);
    Event getEventById(Long id);
    Event createEvent(Event event);
    List<Event> getPastEvents();
    ResponseEntity<Void> deleteEventById(Long event_id);
    List<Event> getEventByStudentIdPetition(Long studentId);
}
