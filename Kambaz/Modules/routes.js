import ModulesDao from "./dao.js";
import { requireFacultyOrAdmin, requireLogin } from "../auth.js";

export default function ModulesRoutes(app) {
  const dao = ModulesDao();

  const findModulesForCourse = async (req, res) => {
    const { courseId } = req.params;
    const modules = await dao.findModulesForCourse(courseId);
    res.json(modules);
  };

  const createModuleForCourse = async (req, res) => {
    const { courseId } = req.params;
    const module = { ...req.body };
    const newModule = await dao.createModule(courseId, module);
    res.json(newModule);
  };

  const deleteModule = async (req, res) => {
    const { courseId, moduleId } = req.params;
    const status = await dao.deleteModule(courseId, moduleId);
    res.json(status);
  };

  const updateModule = async (req, res) => {
    const { courseId, moduleId } = req.params;
    const moduleUpdates = req.body;
    const status = await dao.updateModule(courseId, moduleId, moduleUpdates);
    res.json(status);
  };

  // Reading stays open for the course pages; changes need a signed-in faculty member or admin.
  const canEdit = [requireLogin(), requireFacultyOrAdmin];

  app.get("/api/courses/:courseId/modules", findModulesForCourse);
  app.post("/api/courses/:courseId/modules", ...canEdit, createModuleForCourse);
  app.delete("/api/courses/:courseId/modules/:moduleId", ...canEdit, deleteModule);
  app.put("/api/courses/:courseId/modules/:moduleId", ...canEdit, updateModule);
}