/* ###
 * Standalone Ghidra CodeBrowser Launcher
 *
 * This is a standalone launcher that opens Ghidra CodeBrowser with a specific program.
 * It works with any Ghidra installation without requiring modifications to Ghidra itself.
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra;

import java.io.File;
import java.lang.reflect.Field;

import docking.framework.SplashScreen;
import ghidra.framework.Application;
import ghidra.framework.GhidraApplicationConfiguration;
import ghidra.framework.ToolUtils;
import ghidra.framework.model.*;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.main.FrontEndTool;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.extensions.ExtensionUtils;

/**
 * Launcher for Ghidra that automatically opens CodeBrowser with a specific program.
 *
 * Usage:
 *   launch.sh fg jdk Ghidra 4G "" ghidra.LaunchCodeBrowser <project-path> <program-name>
 *
 * Arguments:
 *   project-path: Full path to .gpr file (e.g., /tmp/test_project/TestProject.gpr)
 *   program-name: Name of program within project (e.g., test_simple)
 *
 * Example:
 *   ./support/launch.sh fg jdk Ghidra 4G "" ghidra.LaunchCodeBrowser \
 *     /tmp/test_project/TestProject.gpr test_simple
 */
public class LaunchCodeBrowser implements GhidraLaunchable {

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) {

		// Validate arguments
		if (args.length < 2) {
			System.err.println("Usage: LaunchCodeBrowser <project-path> <program-name>");
			System.err.println("  project-path: Full path to .gpr file");
			System.err.println("  program-name: Name of program within project");
			System.exit(1);
		}

		String projectPath = args[0];
		String programName = args[1];

		Runnable mainTask = () -> {
			try {
				// Set testing mode to suppress interactive dialogs during E2E testing
				System.setProperty("SystemUtilities.isTesting", "true");

				// Initialize Ghidra application
				GhidraApplicationConfiguration configuration = new GhidraApplicationConfiguration();
				Application.initializeApplication(layout, configuration);

				Msg.info(LaunchCodeBrowser.class, "LaunchCodeBrowser starting...");
				Msg.info(LaunchCodeBrowser.class, "Project: " + projectPath);
				Msg.info(LaunchCodeBrowser.class, "Program: " + programName);
				Msg.info(LaunchCodeBrowser.class, "User: " + SystemUtilities.getUserName());
				Msg.info(LaunchCodeBrowser.class, "User settings directory: " + Application.getUserSettingsDirectory());

				updateSplashScreen("Initializing extensions...");
				ExtensionUtils.initializeExtensions();

				updateSplashScreen("Opening project...");

				// Parse project path
				File projectFile = new File(projectPath);
				if (!projectFile.exists()) {
					Msg.error(LaunchCodeBrowser.class,"Project file does not exist: " + projectPath);
					System.err.println("ERROR: Project file does not exist: " + projectPath);
					System.exit(1);
				}

				String projectDir = projectFile.getParent();
				String projectFileName = projectFile.getName();

				if (!projectFileName.endsWith(ProjectLocator.getProjectExtension())) {
					Msg.error(LaunchCodeBrowser.class,"Invalid project file (must end with .gpr): " + projectPath);
					System.err.println("ERROR: Invalid project file (must end with .gpr): " + projectPath);
					System.exit(1);
				}

				// Open project
				ProjectLocator projectLocator = new ProjectLocator(projectDir, projectFileName);
				ProjectManager projectManager = new LaunchCodeBrowserProjectManager();

				Project project = projectManager.openProject(projectLocator, true, false);
				if (project == null) {
					Msg.error(LaunchCodeBrowser.class,"Failed to open project: " + projectPath);
					System.err.println("ERROR: Failed to open project: " + projectPath);
					System.exit(1);
				}

				Msg.info(LaunchCodeBrowser.class,"Project opened successfully");

				updateSplashScreen("Finding program...");

				// Find the program in the project
				DomainFile domainFile = findProgramInProject(project, programName);
				if (domainFile == null) {
					Msg.error(LaunchCodeBrowser.class,"Program not found in project: " + programName);
					System.err.println("ERROR: Program not found in project: " + programName);
					listAvailablePrograms(project);
					System.exit(1);
				}

				Msg.info(LaunchCodeBrowser.class,"Found program: " + domainFile.getPathname());

				updateSplashScreen("Creating FrontEnd tool...");

				// Create a hidden FrontEndTool to satisfy AppInfo requirements
				// This MUST be done on the Swing thread since FrontEndTool creates GUI components
				FrontEndTool[] frontEndHolder = new FrontEndTool[1];
				SystemUtilities.runSwingNow(() -> {
					frontEndHolder[0] = createHiddenFrontEnd(projectManager, project);
				});
				FrontEndTool frontEndTool = frontEndHolder[0];

				updateSplashScreen("Launching CodeBrowser...");

				// Launch CodeBrowser with the program
				SystemUtilities.runSwingLater(() -> {
					try {
						launchCodeBrowserWithProgram(project, frontEndTool, domainFile);
						Msg.info(LaunchCodeBrowser.class,"CodeBrowser launched successfully");
						Msg.info(LaunchCodeBrowser.class,"LaunchCodeBrowser startup complete");
					} catch (Exception e) {
						Msg.error(LaunchCodeBrowser.class,"Failed to launch CodeBrowser", e);
						System.err.println("ERROR: Failed to launch CodeBrowser: " + e.getMessage());
						e.printStackTrace();
						System.exit(1);
					}
				});

			} catch (Exception e) {
				Msg.error(LaunchCodeBrowser.class,"Fatal error during launch", e);
				System.err.println("FATAL ERROR: " + e.getMessage());
				e.printStackTrace();
				System.exit(1);
			}
		};

		// Start main thread in GhidraThreadGroup
		Thread mainThread = new Thread(new GhidraThreadGroup(), mainTask, "LaunchCodeBrowser");
		mainThread.start();

		// Keep main thread alive to prevent premature exit
		try {
			mainThread.join();
		} catch (InterruptedException e) {
			Msg.warn(LaunchCodeBrowser.class,"Main thread interrupted", e);
		}
	}

	/**
	 * Find a program in the project by name (searches all folders)
	 */
	private DomainFile findProgramInProject(Project project, String programName) {
		DomainFolder rootFolder = project.getProjectData().getRootFolder();
		return findProgramRecursive(rootFolder, programName);
	}

	/**
	 * Recursively search for a program by name
	 */
	private DomainFile findProgramRecursive(DomainFolder folder, String programName) {
		// Check files in current folder
		DomainFile[] files = folder.getFiles();
		for (DomainFile file : files) {
			if (file.getName().equals(programName)) {
				return file;
			}
		}

		// Check subfolders
		DomainFolder[] subfolders = folder.getFolders();
		for (DomainFolder subfolder : subfolders) {
			DomainFile found = findProgramRecursive(subfolder, programName);
			if (found != null) {
				return found;
			}
		}

		return null;
	}

	/**
	 * List all available programs in the project (for error messages)
	 */
	private void listAvailablePrograms(Project project) {
		System.err.println("\nAvailable programs in project:");
		DomainFolder rootFolder = project.getProjectData().getRootFolder();
		listProgramsRecursive(rootFolder, "");
	}

	/**
	 * Recursively list all programs
	 */
	private void listProgramsRecursive(DomainFolder folder, String indent) {
		DomainFile[] files = folder.getFiles();
		for (DomainFile file : files) {
			System.err.println(indent + "  - " + file.getPathname());
		}

		DomainFolder[] subfolders = folder.getFolders();
		for (DomainFolder subfolder : subfolders) {
			System.err.println(indent + subfolder.getName() + "/");
			listProgramsRecursive(subfolder, indent + "  ");
		}
	}

	/**
	 * Prevent the "New Extensions Found" dialog from appearing.
	 *
	 * Uses reflection to clear the newExtensionPlugins set in the tool's ExtensionManager.
	 * This prevents checkForNewExtensions() from showing a blocking dialog on first launch.
	 */
	private void suppressExtensionDialog(PluginTool tool) {
		try {
			// Access the ExtensionManager via reflection
			Class<?> toolClass = tool.getClass();
			while (toolClass != null && !toolClass.getName().contains("GhidraTool")) {
				toolClass = toolClass.getSuperclass();
			}

			if (toolClass == null) {
				Msg.warn(LaunchCodeBrowser.class, "Could not find GhidraTool class for reflection");
				return;
			}

			// Get the extensionManager field
			Field emField = toolClass.getDeclaredField("extensionManager");
			emField.setAccessible(true);
			Object extensionManager = emField.get(tool);

			if (extensionManager == null) {
				Msg.warn(LaunchCodeBrowser.class, "ExtensionManager is null");
				return;
			}

			// Get the newExtensionPlugins set
			Class<?> emClass = extensionManager.getClass();
			Field pluginsField = emClass.getDeclaredField("newExtensionPlugins");
			pluginsField.setAccessible(true);
			Object pluginsSet = pluginsField.get(extensionManager);

			if (pluginsSet != null && pluginsSet instanceof java.util.Set) {
				@SuppressWarnings("unchecked")
				java.util.Set<Class<?>> newPlugins = (java.util.Set<Class<?>>) pluginsSet;

				if (!newPlugins.isEmpty()) {
					Msg.info(LaunchCodeBrowser.class,
						"Found " + newPlugins.size() + " new extension plugin(s), auto-enabling...");

					// Enable each new extension plugin before clearing the set
					// Must be done on Swing thread
					final java.util.List<Class<?>> pluginList = new java.util.ArrayList<>(newPlugins);
					SystemUtilities.runSwingNow(() -> {
						for (Class<?> pluginClass : pluginList) {
							try {
								String className = pluginClass.getName();
								Msg.info(LaunchCodeBrowser.class, "Enabling plugin: " + className);
								tool.addPlugin(className);
								Msg.info(LaunchCodeBrowser.class, "Successfully enabled: " + className);
							} catch (Exception e) {
								Msg.error(LaunchCodeBrowser.class,
									"Failed to enable plugin " + pluginClass.getName(), e);
							}
						}
					});

					// Now clear the set to prevent the dialog from showing
					newPlugins.clear();
					Msg.info(LaunchCodeBrowser.class, "Suppressed extension dialog");
				}
			}
		} catch (Exception e) {
			Msg.warn(LaunchCodeBrowser.class,
				"Could not suppress extension dialog via reflection: " + e.getMessage());
			// Non-fatal - dialog may appear but won't prevent operation
		}
	}

	/**
	 * Create a hidden FrontEndTool to satisfy AppInfo requirements.
	 * Some plugins in CodeBrowser require FrontEnd to be initialized.
	 *
	 * IMPORTANT: This method MUST be called on the Swing EDT because FrontEndTool
	 * creates GUI components (MenuManager, etc.). The caller should use:
	 * SystemUtilities.runSwingNow(() -> createHiddenFrontEnd(...))
	 */
	private FrontEndTool createHiddenFrontEnd(ProjectManager projectManager, Project project) {
		Msg.info(LaunchCodeBrowser.class, "Creating hidden FrontEndTool on Swing thread...");

		// Create FrontEndTool (Project Window) but don't show it
		// NOTE: This creates GUI components, so it MUST run on Swing EDT
		FrontEndTool frontEndTool = new FrontEndTool(projectManager);
		frontEndTool.setActiveProject(project);

		// Don't call setVisible(true) - keep it hidden
		// The FrontEnd just needs to exist to satisfy AppInfo

		Msg.info(LaunchCodeBrowser.class, "FrontEndTool created (hidden)");
		return frontEndTool;
	}

	/**
	 * Launch CodeBrowser tool with the specified program directly from template.
	 * Requires a FrontEndTool to exist (even if hidden) for AppInfo.
	 */
	private void launchCodeBrowserWithProgram(Project project, FrontEndTool frontEndTool,
			DomainFile domainFile) throws Exception {
		// Read the CodeBrowser tool template
		ToolTemplate toolTemplate = ToolUtils.readToolTemplate("defaultTools/CodeBrowser.tool");
		if (toolTemplate == null) {
			throw new Exception("Failed to load CodeBrowser tool template");
		}

		Msg.info(LaunchCodeBrowser.class, "Creating CodeBrowser tool from template...");

		// Create the tool directly from the template
		PluginTool tool = toolTemplate.createTool(project);

		if (tool == null) {
			throw new Exception("Failed to create CodeBrowser tool from template");
		}

		// CRITICAL FIX: Suppress "New Extensions Found" dialog
		// Clear the newExtensionPlugins set before making the tool visible
		suppressExtensionDialog(tool);

		Msg.info(LaunchCodeBrowser.class, "CodeBrowser tool created successfully");

		// Make tool visible BEFORE opening program (important for GUI initialization)
		tool.setVisible(true);

		// Open the program in the tool
		Msg.info(LaunchCodeBrowser.class, "Opening program in CodeBrowser...");
		ProgramManager programManager = tool.getService(ProgramManager.class);
		if (programManager == null) {
			throw new Exception("ProgramManager service not available in CodeBrowser");
		}

		// Open the program as the current program
		programManager.openProgram(domainFile, DomainFile.DEFAULT_VERSION,
			ProgramManager.OPEN_CURRENT);

		Program currentProgram = programManager.getCurrentProgram();
		if (currentProgram == null) {
			throw new Exception("Failed to open program in CodeBrowser");
		}

		Msg.info(LaunchCodeBrowser.class, "Program loaded in CodeBrowser: " + currentProgram.getName());

		// Add shutdown hook for clean exit
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			Msg.info(LaunchCodeBrowser.class, "Shutting down CodeBrowser...");
			try {
				tool.close();
			} catch (Exception e) {
				// Ignore errors during shutdown
			}
			Msg.info(LaunchCodeBrowser.class, "Shutdown complete");
		}));
	}

	/**
	 * Update splash screen message (if visible)
	 */
	private void updateSplashScreen(String message) {
		SystemUtilities.runSwingNow(() -> SplashScreen.updateSplashScreenStatus(message));
	}

	/**
	 * Main method for standalone execution (not typically used - use launch.sh instead)
	 */
	public static void main(String[] args) throws Exception {
		if (args.length < 2) {
			System.err.println("Usage: LaunchCodeBrowser <project-path> <program-name>");
			System.err.println("  project-path: Full path to .gpr file");
			System.err.println("  program-name: Name of program within project");
			System.err.println("\nExample:");
			System.err.println("  LaunchCodeBrowser /tmp/test_project/TestProject.gpr test_simple");
			System.exit(1);
		}

		// This main method is here for reference but typically you would use:
		// ./support/launch.sh fg jdk Ghidra 4G "" ghidra.LaunchCodeBrowser <args>
		System.err.println("Please use launch.sh to run this class:");
		System.err.println("  ./support/launch.sh fg jdk Ghidra 4G \"\" ghidra.LaunchCodeBrowser " +
			String.join(" ", args));
		System.exit(1);
	}

	/**
	 * Nested class to access DefaultProjectManager's protected constructor
	 */
	private static class LaunchCodeBrowserProjectManager extends DefaultProjectManager {
		// This exists just to allow access to the constructor
	}
}
