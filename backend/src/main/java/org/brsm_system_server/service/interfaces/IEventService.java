package org.brsm_system_server.service.interfaces;

import org.brsm_system_server.entity.Event;

import java.util.List;

public interface IEventService {
    List<Event> getEventsByStudentId(Long studentId);
}
