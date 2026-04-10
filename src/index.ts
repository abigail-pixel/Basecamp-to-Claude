#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { config } from 'dotenv';
import express from 'express';
import { BasecampClient } from './lib/basecamp-client.js';
import { tokenStorage } from './lib/token-storage.js';
import type { MCPToolResult } from './types/basecamp.js';

// Load environment variables
config();

class BasecampMCPServer {
  private server: Server;
  private basecampClient: BasecampClient | null = null;

  constructor() {
    this.server = new Server(
      {
        name: 'basecamp-mcp-server',
        version: '1.0.0',
      }
    );

    this.setupHandlers();
    this.setupErrorHandling();
  }

  private setupErrorHandling(): void {
    this.server.onerror = (error) => {
      console.error('[MCP Server Error]', error);
    };
  }

  private async getBasecampClient(): Promise<BasecampClient> {
    const isExpired = await tokenStorage.isTokenExpired();

    // Return cached client only if token is still valid
    if (this.basecampClient && !isExpired) {
      return this.basecampClient;
    }

    // Clear cached client if token has expired
    if (isExpired) {
      this.basecampClient = null;
      const refreshed = await tokenStorage.refreshAccessToken();
      if (!refreshed) {
        throw new McpError(
          ErrorCode.InvalidRequest,
          'OAuth token expired and refresh failed. Please re-authenticate: npm run auth'
        );
      }
    }

    const tokenData = await tokenStorage.getToken();
    if (!tokenData?.accessToken) {
      throw new McpError(
        ErrorCode.InvalidRequest,
        'Authentication required. Please run OAuth authentication first: npm run auth'
      );
    }

    const accountId = tokenData.accountId || process.env.BASECAMP_ACCOUNT_ID;
    const userAgent = process.env.USER_AGENT || 'Basecamp MCP Server (mcp@basecamp-server.dev)';

    if (!accountId) {
      throw new McpError(
        ErrorCode.InvalidRequest,
        'Missing BASECAMP_ACCOUNT_ID. Please set it in your .env file.'
      );
    }

    this.basecampClient = new BasecampClient({
      accessToken: tokenData.accessToken,
      accountId,
      userAgent,
      authMode: 'oauth',
    });

    return this.basecampClient;
  }

  private async handleError(error: any): Promise<MCPToolResult> {
    if (error.response?.status === 401 && error.response?.data?.error?.includes('expired')) {
      return {
        status: 'error',
        error: 'OAuth token expired',
        message: 'Your Basecamp OAuth token has expired. Please re-authenticate: npm run auth'
      };
    }

    return {
      status: 'error',
      error: 'Execution error',
      message: error.message || 'Unknown error occurred'
    };
  }

  private setupHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          // Core tools
          {
            name: 'get_projects',
            description: 'Get all Basecamp projects',
            inputSchema: {
              type: 'object',
              properties: {},
            },
          },
          {
            name: 'get_project',
            description: 'Get details for a specific project',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
              },
              required: ['project_id'],
            },
          },
          {
            name: 'search_basecamp',
            description: 'Search across Basecamp projects, todos, and messages',
            inputSchema: {
              type: 'object',
              properties: {
                query: { type: 'string', description: 'Search query' },
                project_id: { type: 'string', description: 'Optional project ID to limit search scope' },
              },
              required: ['query'],
            },
          },
          {
            name: 'global_search',
            description: 'Search projects, todos and campfire messages across all projects',
            inputSchema: {
              type: 'object',
              properties: {
                query: { type: 'string', description: 'Search query' },
              },
              required: ['query'],
            },
          },

          // Todo tools
          {
            name: 'get_todolists',
            description: 'Get todo lists for a project',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
              },
              required: ['project_id'],
            },
          },
          {
            name: 'get_todos',
            description: 'Get todos from a todo list',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'Project ID' },
                todolist_id: { type: 'string', description: 'The todo list ID' },
              },
              required: ['project_id', 'todolist_id'],
            },
          },

          // Card Table tools
          {
            name: 'get_card_table',
            description: 'Get the card table details for a project',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
              },
              required: ['project_id'],
            },
          },
          {
            name: 'get_columns',
            description: 'Get all columns in a card table',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                card_table_id: { type: 'string', description: 'The card table ID' },
              },
              required: ['project_id', 'card_table_id'],
            },
          },
          {
            name: 'get_cards',
            description: 'Get all cards in a column',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                column_id: { type: 'string', description: 'The column ID' },
              },
              required: ['project_id', 'column_id'],
            },
          },
          {
            name: 'create_card',
            description: 'Create a new card in a column',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                column_id: { type: 'string', description: 'The column ID' },
                title: { type: 'string', description: 'The card title' },
                content: { type: 'string', description: 'Optional card content/description' },
                due_on: { type: 'string', description: 'Optional due date (ISO 8601 format)' },
                notify: { type: 'boolean', description: 'Whether to notify assignees (default: false)' },
              },
              required: ['project_id', 'column_id', 'title'],
            },
          },

          // Column Management tools
          {
            name: 'create_column',
            description: 'Create a new column in a card table',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                card_table_id: { type: 'string', description: 'The card table ID' },
                title: { type: 'string', description: 'The column title' },
              },
              required: ['project_id', 'card_table_id', 'title'],
            },
          },
          {
            name: 'update_column',
            description: 'Update a column title',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                column_id: { type: 'string', description: 'The column ID' },
                title: { type: 'string', description: 'The new column title' },
              },
              required: ['project_id', 'column_id', 'title'],
            },
          },
          {
            name: 'move_column',
            description: 'Move a column to a new position',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                card_table_id: { type: 'string', description: 'The card table ID' },
                column_id: { type: 'string', description: 'The column ID' },
                position: { type: 'number', description: 'The new 1-based position' },
              },
              required: ['project_id', 'card_table_id', 'column_id', 'position'],
            },
          },
          {
            name: 'update_column_color',
            description: 'Update a column color',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                column_id: { type: 'string', description: 'The column ID' },
                color: { type: 'string', description: 'The hex color code (e.g., #FF0000)' },
              },
              required: ['project_id', 'column_id', 'color'],
            },
          },

          // Card Management tools
          {
            name: 'get_card',
            description: 'Get details for a specific card',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                card_id: { type: 'string', description: 'The card ID' },
              },
              required: ['project_id', 'card_id'],
            },
          },
          {
            name: 'update_card',
            description: 'Update a card',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                card_id: { type: 'string', description: 'The card ID' },
                title: { type: 'string', description: 'The new card title' },
                content: { type: 'string', description: 'The new card content/description' },
                due_on: { type: 'string', description: 'Due date (ISO 8601 format)' },
                assignee_ids: { type: 'array', items: { type: 'string' }, description: 'Array of person IDs to assign to the card' },
              },
              required: ['project_id', 'card_id'],
            },
          },
          {
            name: 'move_card',
            description: 'Move a card to a new column',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                card_id: { type: 'string', description: 'The card ID' },
                column_id: { type: 'string', description: 'The destination column ID' },
              },
              required: ['project_id', 'card_id', 'column_id'],
            },
          },
          {
            name: 'complete_card',
            description: 'Mark a card as complete',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                card_id: { type: 'string', description: 'The card ID' },
              },
              required: ['project_id', 'card_id'],
            },
          },

          // Card Steps tools
          {
            name: 'get_card_steps',
            description: 'Get all steps (sub-tasks) for a card',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                card_id: { type: 'string', description: 'The card ID' },
              },
              required: ['project_id', 'card_id'],
            },
          },
          {
            name: 'create_card_step',
            description: 'Create a new step (sub-task) for a card',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                card_id: { type: 'string', description: 'The card ID' },
                title: { type: 'string', description: 'The step title' },
                due_on: { type: 'string', description: 'Optional due date (ISO 8601 format)' },
                assignee_ids: { type: 'array', items: { type: 'string' }, description: 'Array of person IDs to assign to the step' },
              },
              required: ['project_id', 'card_id', 'title'],
            },
          },
          {
            name: 'complete_card_step',
            description: 'Mark a card step as complete',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                step_id: { type: 'string', description: 'The step ID' },
              },
              required: ['project_id', 'step_id'],
            },
          },

          // Communication tools
          {
            name: 'get_campfire_lines',
            description: 'Get recent messages from a Basecamp campfire (chat room)',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                campfire_id: { type: 'string', description: 'The campfire/chat room ID' },
              },
              required: ['project_id', 'campfire_id'],
            },
          },
          {
            name: 'get_comments',
            description: 'Get comments for a Basecamp item',
            inputSchema: {
              type: 'object',
              properties: {
                recording_id: { type: 'string', description: 'The item ID' },
                project_id: { type: 'string', description: 'The project ID' },
              },
              required: ['recording_id', 'project_id'],
            },
          },

          // Document tools
          {
            name: 'get_documents',
            description: 'List documents in a vault',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'Project ID' },
                vault_id: { type: 'string', description: 'Vault ID' },
              },
              required: ['project_id', 'vault_id'],
            },
          },
          {
            name: 'create_document',
            description: 'Create a document in a vault',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'Project ID' },
                vault_id: { type: 'string', description: 'Vault ID' },
                title: { type: 'string', description: 'Document title' },
                content: { type: 'string', description: 'Document HTML content' },
              },
              required: ['project_id', 'vault_id', 'title', 'content'],
            },
          },
          {
            name: 'update_document',
            description: 'Update a document',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'Project ID' },
                document_id: { type: 'string', description: 'Document ID' },
                title: { type: 'string', description: 'New title' },
                content: { type: 'string', description: 'New HTML content' },
              },
              required: ['project_id', 'document_id'],
            },
          },
          {
            name: 'trash_document',
            description: 'Move a document to trash',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'Project ID' },
                document_id: { type: 'string', description: 'Document ID' },
              },
              required: ['project_id', 'document_id'],
            },
          },

          // File tools
          {
            name: 'get_uploads',
            description: 'List uploads in a project or vault',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'Project ID' },
                vault_id: { type: 'string', description: 'Optional vault ID to limit to specific vault' },
              },
              required: ['project_id'],
            },
          },

          // Webhook tools
          {
            name: 'get_webhooks',
            description: 'List webhooks for a project',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'Project ID' },
              },
              required: ['project_id'],
            },
          },
          {
            name: 'create_webhook',
            description: 'Create a webhook',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'Project ID' },
                payload_url: { type: 'string', description: 'Payload URL' },
                types: { type: 'array', items: { type: 'string' }, description: 'Event types' },
              },
              required: ['project_id', 'payload_url'],
            },
          },
          {
            name: 'delete_webhook',
            description: 'Delete a webhook',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'Project ID' },
                webhook_id: { type: 'string', description: 'Webhook ID' },
              },
              required: ['project_id', 'webhook_id'],
            },
          },

          // Check-in tools
          {
            name: 'get_daily_check_ins',
            description: "Get project's daily checking questionnaire",
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                page: { type: 'number', description: 'Page number for paginated response' },
              },
              required: ['project_id'],
            },
          },
          {
            name: 'get_question_answers',
            description: 'Get answers on daily check-in question',
            inputSchema: {
              type: 'object',
              properties: {
                project_id: { type: 'string', description: 'The project ID' },
                question_id: { type: 'string', description: 'The question ID' },
                page: { type: 'number', description: 'Page number for paginated response' },
              },
              required: ['project_id', 'question_id'],
            },
          },
        ],
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const client = await this.getBasecampClient();
        
        // Type assertion for args - MCP ensures args are provided for required fields
        const typedArgs = args as Record<string, any>;

        switch (name) {
          case 'get_projects': {
            const projects = await client.getProjects();
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  projects,
                  count: projects.length
                }, null, 2)
              }]
            };
          }

          case 'get_project': {
            const project = await client.getProject(typedArgs.project_id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  project
                }, null, 2)
              }]
            };
          }

          case 'get_todolists': {
            const todolists = await client.getTodoLists(typedArgs.project_id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  todolists,
                  count: todolists.length
                }, null, 2)
              }]
            };
          }

          case 'get_todos': {
            const todos = await client.getTodos(typedArgs.project_id, typedArgs.todolist_id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  todos,
                  count: todos.length
                }, null, 2)
              }]
            };
          }

          case 'get_card_table': {
            const cardTable = await client.getCardTable(typedArgs.project_id);
            const cardTableDetails = await client.getCardTableDetails(typedArgs.project_id, cardTable.id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  card_table: cardTableDetails
                }, null, 2)
              }]
            };
          }

          case 'get_columns': {
            const columns = await client.getColumns(typedArgs.project_id, typedArgs.card_table_id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  columns,
                  count: columns.length
                }, null, 2)
              }]
            };
          }

          case 'get_cards': {
            const cards = await client.getCards(typedArgs.project_id, typedArgs.column_id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  cards,
                  count: cards.length
                }, null, 2)
              }]
            };
          }

          case 'create_card': {
            const card = await client.createCard(
              typedArgs.project_id,
              typedArgs.column_id,
              typedArgs.title,
              typedArgs.content,
              typedArgs.due_on,
              typedArgs.notify || false
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  card,
                  message: `Card '${typedArgs.title}' created successfully`
                }, null, 2)
              }]
            };
          }

          case 'create_column': {
            const column = await client.createColumn(typedArgs.project_id, typedArgs.card_table_id, typedArgs.title);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  column,
                  message: `Column '${typedArgs.title}' created successfully`
                }, null, 2)
              }]
            };
          }

          case 'move_card': {
            await client.moveCard(typedArgs.project_id, typedArgs.card_id, typedArgs.column_id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  message: `Card moved to column ${typedArgs.column_id}`
                }, null, 2)
              }]
            };
          }

          case 'complete_card': {
            await client.completeCard(typedArgs.project_id, typedArgs.card_id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  message: 'Card marked as complete'
                }, null, 2)
              }]
            };
          }

          case 'get_card_steps': {
            const steps = await client.getCardSteps(typedArgs.project_id, typedArgs.card_id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  steps,
                  count: steps.length
                }, null, 2)
              }]
            };
          }

          case 'create_card_step': {
            const step = await client.createCardStep(
              typedArgs.project_id,
              typedArgs.card_id,
              typedArgs.title,
              typedArgs.due_on,
              typedArgs.assignee_ids
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  step,
                  message: `Step '${typedArgs.title}' created successfully`
                }, null, 2)
              }]
            };
          }

          case 'complete_card_step': {
            await client.completeCardStep(typedArgs.project_id, typedArgs.step_id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  message: 'Step marked as complete'
                }, null, 2)
              }]
            };
          }

          case 'get_campfire_lines': {
            const lines = await client.getCampfireLines(typedArgs.project_id, typedArgs.campfire_id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  campfire_lines: lines,
                  count: lines.length
                }, null, 2)
              }]
            };
          }

          case 'get_comments': {
            const comments = await client.getComments(typedArgs.project_id, typedArgs.recording_id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  comments,
                  count: comments.length
                }, null, 2)
              }]
            };
          }

          case 'get_documents': {
            const documents = await client.getDocuments(typedArgs.project_id, typedArgs.vault_id);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  documents,
                  count: documents.length
                }, null, 2)
              }]
            };
          }

          case 'create_document': {
            const document = await client.createDocument(
              typedArgs.project_id,
              typedArgs.vault_id,
              typedArgs.title,
              typedArgs.content
            );
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  document
                }, null, 2)
              }]
            };
          }

          case 'get_daily_check_ins': {
            const checkIns = await client.getDailyCheckIns(typedArgs.project_id, typedArgs.page || 1);
            return {
              content: [{
                type: 'text',
                text: JSON.stringify({
                  status: 'success',
                  daily_check_ins: checkIns,
                  count: checkIns.length
                }, null, 2)
              }]
            };
          }

          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }
      } catch (error: any) {
        const errorResult = await this.handleError(error);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(errorResult, null, 2)
          }]
        };
      }
    });
  }

  async run(transport?: StdioServerTransport | SSEServerTransport): Promise<void> {
    const t = transport ?? new StdioServerTransport();
    await this.server.connect(t);
    if (!transport) {
      console.error('Basecamp MCP server running on stdio');
    }
  }

  async close(): Promise<void> {
    await this.server.close();
  }
}

// Export the server class for testing
export { BasecampMCPServer };

// Create server function for CLI usage
export function createServer(): BasecampMCPServer {
  return new BasecampMCPServer();
}

// Start server function for CLI usage
export async function startServer(): Promise<void> {
  const server = new BasecampMCPServer();
  await server.run();
}

async function startHttpServer(): Promise<void> {
  const authToken = process.env.MCP_AUTH_TOKEN;
  if (!authToken) {
    console.error('MCP_AUTH_TOKEN environment variable is required in HTTP mode');
    process.exit(1);
  }

  const app = express();
  app.use(express.json());

  // CORS headers required for browser-based MCP clients
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  // Bearer token authentication middleware
  const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
    const authHeader = req.headers.authorization;
    if (!authHeader || authHeader !== `Bearer ${authToken}`) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    next();
  };

  // Map session IDs to active transports for message routing
  const transports = new Map<string, SSEServerTransport>();

  // SSE endpoint — establishes MCP connection
  app.get('/sse', requireAuth, async (req, res) => {
    const mcpServer = new BasecampMCPServer();
    const transport = new SSEServerTransport('/messages', res as any);

    transports.set(transport.sessionId, transport);
    transport.onclose = () => {
      transports.delete(transport.sessionId);
    };

    await mcpServer.run(transport);
  });

  // Message endpoint — receives MCP messages from client
  app.post('/messages', requireAuth, async (req, res) => {
    const sessionId = req.query.sessionId as string;
    const transport = transports.get(sessionId);

    if (!transport) {
      res.status(400).json({ error: 'No active session' });
      return;
    }

    await transport.handlePostMessage(req as any, res as any);
  });

  // Health check — no auth required
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', service: 'basecamp-mcp-server' });
  });

  const port = parseInt(process.env.PORT || '3000');
  app.listen(port, () => {
    console.error(`Basecamp MCP server running on HTTP port ${port}`);
  });
}

// Start the server if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.env.PORT) {
    // HTTP mode — used when deployed (Railway, Render, etc.)
    startHttpServer().catch((error) => {
      console.error('Failed to start HTTP server:', error);
      process.exit(1);
    });
  } else {
    // Stdio mode — used locally with Claude Desktop / Cursor
    const server = new BasecampMCPServer();
    process.on('SIGINT', async () => {
      await server.close();
      process.exit(0);
    });
    server.run().catch((error) => {
      console.error('Failed to start server:', error);
      process.exit(1);
    });
  }
}
