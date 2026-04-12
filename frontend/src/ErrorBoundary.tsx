import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  err: Error | null
  info: ErrorInfo | null
}

/**
 * Catches render errors so a failed panel does not leave a blank #root.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { err: null, info: null }

  static getDerivedStateFromError(err: Error): Partial<State> {
    return { err }
  }

  override componentDidCatch(err: Error, info: ErrorInfo) {
    console.error('[arena UI]', err, info.componentStack)
    this.setState({ info })
  }

  override render() {
    if (this.state.err) {
      return (
        <div
          style={{
            minHeight: '100vh',
            padding: 24,
            fontFamily: 'system-ui, sans-serif',
            background: '#fafaf9',
            color: '#1c1917',
          }}
        >
          <h1 style={{ fontSize: 18, marginBottom: 12 }}>arena — UI error</h1>
          <p style={{ marginBottom: 8, color: '#57534e' }}>
            Something threw while rendering. Open the browser console (F12) for the full stack.
          </p>
          <pre
            style={{
              padding: 12,
              background: '#fff',
              border: '1px solid #d6d3d1',
              borderRadius: 8,
              overflow: 'auto',
              fontSize: 13,
              whiteSpace: 'pre-wrap',
            }}
          >
            {this.state.err.message}
            {'\n\n'}
            {this.state.err.stack}
            {this.state.info?.componentStack ?? ''}
          </pre>
        </div>
      )
    }
    return this.props.children
  }
}
