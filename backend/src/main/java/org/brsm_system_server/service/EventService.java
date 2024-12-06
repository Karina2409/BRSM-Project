package org.brsm_system_server.service;

import org.brsm_system_server.entity.Event;
import org.brsm_system_server.repository.EventRepository;
import org.brsm_system_server.service.interfaces.IEventService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class EventService implements IEventService {

    @Autowired
    private EventRepository eventRepository;

    @Override
    public List<Event> findAllEvents(){
        return eventRepository.findAll(Sort.by(Sort.Direction.DESC, "eventDate"));
    }

    @Override
    public List<Event> getEventsByStudentId(Long studentId) {
        return eventRepository.findEventsByStudentId(studentId);
    }

    @Override
    public Event getEventById(Long id){
        Optional<Event> optionalEvent = eventRepository.findById(id);
        return optionalEvent.orElse(null);
    }
}
