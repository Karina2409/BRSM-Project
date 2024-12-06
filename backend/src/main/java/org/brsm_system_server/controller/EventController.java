package org.brsm_system_server.controller;

import org.brsm_system_server.dto.EventDTO;
import org.brsm_system_server.dto.StudentDTO;
import org.brsm_system_server.entity.Event;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.mapper.StudentMapper;
import org.brsm_system_server.service.interfaces.IEventService;
import org.brsm_system_server.service.interfaces.IStudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.brsm_system_server.mapper.EventMapper;

import java.util.List;

@RestController
@RequestMapping("/events")
public class EventController {

    @Autowired
    private IEventService eventService;

    @Autowired
    private IStudentService studentService;

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @GetMapping("/get-all")
    public List<EventDTO> getEvents() {
        List<Event> events = eventService.findAllEvents();
        return events.stream().map(EventMapper::toDto).toList();
    }

    @GetMapping("/{eventId}")
    public EventDTO getEventById(@PathVariable Long eventId) {
        Event event = eventService.getEventById(eventId);
        return EventMapper.toDto(event);
    }

    @GetMapping("/{eventId}/students")
    public List<StudentDTO> getStudentsByEventId(@PathVariable Long eventId) {
        List<Student> students = studentService.getStudentsByEventId(eventId);
        return students.stream().map(student -> {
            return StudentMapper.toDto(student, eventService);
        }).toList();
    }

}
