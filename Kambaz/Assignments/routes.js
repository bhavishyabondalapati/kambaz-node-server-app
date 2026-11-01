import AssignmentsDao from "./dao.js";
import { requireFacultyOrAdmin, requireLogin } from "../auth.js";

export default function AssignmentsRoutes(app) {
  const dao = AssignmentsDao();

  const findAssignmentsForCourse = async (req, res) => {
    const { courseId } = req.params;
    const assignments = await dao.findAssignmentsForCourse(courseId);
    const assignmentsArray = assignments.map(a => a.toObject ? a.toObject() : a);
    res.json(assignmentsArray);
  };

  const createAssignmentForCourse = async (req, res) => {
    const { courseId } = req.params;
    const assignment = {
      ...req.body,
      course: courseId,
    };
    const newAssignment = await dao.createAssignment(assignment);
    const assignmentObject = newAssignment.toObject ? newAssignment.toObject() : newAssignment;
    res.json(assignmentObject);
  };

  const deleteAssignment = async (req, res) => {
    const { assignmentId } = req.params;
    const status = await dao.deleteAssignment(assignmentId);
    res.json(status);
  };

  const updateAssignment = async (req, res) => {
    const { assignmentId } = req.params;
    const assignmentUpdates = req.body;
    const status = await dao.updateAssignment(assignmentId, assignmentUpdates);
    res.json(status);
  };

  const findAssignmentById = async (req, res) => {
    const { assignmentId } = req.params;
    const assignment = await dao.findAssignmentById(assignmentId);
    const assignmentObject = assignment.toObject ? assignment.toObject() : assignment;
    res.json(assignmentObject);
  };

  // Reading stays open for the course pages; changes need a signed-in faculty member or admin.
  const canEdit = [requireLogin(), requireFacultyOrAdmin];

  app.get("/api/courses/:courseId/assignments", findAssignmentsForCourse);
  app.post("/api/courses/:courseId/assignments", ...canEdit, createAssignmentForCourse);
  app.delete("/api/assignments/:assignmentId", ...canEdit, deleteAssignment);
  app.put("/api/assignments/:assignmentId", ...canEdit, updateAssignment);
  app.get("/api/assignments/:assignmentId", findAssignmentById);
}